package ingress

import (
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/appscode/errors"
	"github.com/appscode/log"
	"github.com/appscode/voyager/api"
	kapi "k8s.io/kubernetes/pkg/api"
	kerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/unversioned"
	kepi "k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/util/intstr"
)

func (lbc *EngressController) Create() error {
	log.Debugln("Starting creating lb. got engress with", lbc.Resource.ObjectMeta)
	err := lbc.parse()
	if err != nil {
		return errors.FromErr(err).Err()
	}
	err = lbc.generateTemplate()
	if err != nil {
		return errors.FromErr(err).Err()
	}

	err = lbc.ensureConfigMap()
	if err != nil {
		return errors.FromErr(err).Err()
	}
	time.Sleep(time.Second * 5)
	err = lbc.createLB()
	if err != nil {
		return errors.FromErr(err).Err()
	}

	if lbc.Parsed.Stats {
		lbc.ensureStatsService()
	}
	return nil
}

func (lbc *EngressController) ensureConfigMap() error {
	log.Infoln("creating cmap for engress")
	cm, err := lbc.KubeClient.Core().ConfigMaps(lbc.Resource.Namespace).Get(lbc.Resource.OffshootName())
	if kerr.IsNotFound(err) {
		cm = &kapi.ConfigMap{
			ObjectMeta: kapi.ObjectMeta{
				Name:      lbc.Resource.OffshootName(),
				Namespace: lbc.Resource.Namespace,
				Annotations: map[string]string{
					api.OriginAPISchema: lbc.Resource.APISchema(),
					api.OriginName:      lbc.Resource.GetName(),
				},
			},
			Data: map[string]string{
				"haproxy.cfg": lbc.ConfigData,
			},
		}
		_, err = lbc.KubeClient.Core().ConfigMaps(lbc.Resource.Namespace).Create(cm)
		return err
	} else if err != nil {
		return errors.FromErr(err).Err()
	}

	needsUpdate := false
	if val, ok := lbc.ensureResourceAnnotations(cm.Annotations); ok {
		needsUpdate = true
		cm.Annotations = val
	}

	cmData := map[string]string{
		"haproxy.cfg": lbc.ConfigData,
	}
	if !reflect.DeepEqual(cm.Data, cmData) {
		needsUpdate = true
		cm.Data = cmData
	}

	if needsUpdate {
		_, err = lbc.KubeClient.Core().ConfigMaps(lbc.Resource.Namespace).Update(cm)
		return err
	}
	return nil
}

func (lbc *EngressController) createLB() error {
	if lbc.Resource.LBType() == api.LBTypeDaemon || lbc.Resource.LBType() == api.LBTypeHostPort {
		err := lbc.createHostPortPods()
		if err != nil {
			return errors.FromErr(err).Err()
		}
		time.Sleep(time.Second * 10)
		err = lbc.createHostPortSvc()
		if err != nil {
			return errors.FromErr(err).Err()
		}
	} else if lbc.Resource.LBType() == api.LBTypeNodePort {
		err := lbc.createNodePortPods()
		if err != nil {
			return errors.FromErr(err).Err()
		}
		time.Sleep(time.Second * 10)
		err = lbc.createNodePortSvc()
		if err != nil {
			return errors.FromErr(err).Err()
		}
	} else {
		if lbc.SupportsLoadBalancerType() {
			// deleteResidualPods is a safety checking deletation of previous version RC
			// This should Ignore error.
			lbc.deleteResidualPods()
			err := lbc.createNodePortPods()
			if err != nil {
				return errors.FromErr(err).Err()
			}
			time.Sleep(time.Second * 10)
			err = lbc.createLoadBalancerSvc()
			if err != nil {
				return errors.FromErr(err).Err()
			}
			go lbc.updateStatus()
		} else {
			return errors.New("LoadBalancer type ingress is unsupported for cloud provider:", lbc.ProviderName).Err()
		}
	}
	return nil
}

func (lbc *EngressController) createHostPortSvc() error {
	// Create a Headless service without selectors
	// We just want kubernetes to assign a stable UID to the service. This is used inside EnsureFirewall()
	svc := &kapi.Service{
		ObjectMeta: kapi.ObjectMeta{
			Name:      lbc.Resource.OffshootName(),
			Namespace: lbc.Resource.Namespace,
			Annotations: map[string]string{
				api.OriginAPISchema: lbc.Resource.APISchema(),
				api.OriginName:      lbc.Resource.GetName(),
			},
		},

		Spec: kapi.ServiceSpec{
			Type:      kapi.ServiceTypeClusterIP,
			ClusterIP: "None",
			Ports:     []kapi.ServicePort{},
		},
	}

	// opening other tcp ports
	for _, port := range lbc.Ports {
		p := kapi.ServicePort{
			Name:       "tcp-" + strconv.Itoa(port),
			Protocol:   "TCP",
			Port:       int32(port),
			TargetPort: intstr.FromInt(port),
		}
		svc.Spec.Ports = append(svc.Spec.Ports, p)
	}

	if ans, ok := lbc.Resource.ServiceAnnotations(lbc.ProviderName); ok {
		for k, v := range ans {
			svc.Annotations[k] = v
		}
	}

	updateFW := false
	s, err := lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Get(svc.Name)
	if kerr.IsNotFound(err) {
		svc, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Create(svc)
		if err != nil {
			return errors.FromErr(err).Err()
		}
		updateFW = true
	} else if err != nil {
		return errors.FromErr(err).Err()
	} else {
		needsUpdate := false
		if val, ok := lbc.ensureResourceAnnotations(s.Annotations); ok {
			s.Annotations = val
			needsUpdate = true
		}

		if isServicePortChanged(s.Spec.Ports, svc.Spec.Ports) {
			needsUpdate = true
			s.Spec.Ports = svc.Spec.Ports

			// Port changed, need to update Firewall
			updateFW = true
		}

		if needsUpdate {
			_, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Update(s)
			if err != nil {
				return errors.FromErr(err).Err()
			}
		}
	}

	if updateFW && lbc.CloudManager != nil {
		daemonNodes, err := lbc.KubeClient.Core().Nodes().List(kapi.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set(lbc.Resource.NodeSelector())),
		})
		if err != nil {
			log.Infoln("node not found with nodeSelector, cause", err)
			return errors.FromErr(err).Err()
		}
		// open up firewall
		log.Debugln("Checking cloud manager", lbc.CloudManager)
		if fw, ok := lbc.CloudManager.Firewall(); ok {
			log.Debugln("firewalls found")
			convertedSvc := &kapi.Service{}
			kapi.Scheme.Convert(svc, convertedSvc, nil)
			for _, node := range daemonNodes.Items {
				err = fw.EnsureFirewall(convertedSvc, node.Name)
				if err != nil {
					log.Errorln("Failed to ensure loadbalancer for node", node.Name, "cause", err)
				}
			}
			log.Debugln("getting firewalls for cloud manager failed")
		}
	}
	return nil
}

func (lbc *EngressController) createHostPortPods() error {
	if len(lbc.Resource.NodeSelector()) == 0 {
		return errors.Newf("%s type ingress %s@%s is missing node selectors.", lbc.Resource.LBType(), lbc.Resource.Name, lbc.Resource.Namespace).Err()
	}
	log.Infoln("Creating Daemon type lb for nodeSelector = ", lbc.Resource.NodeSelector())

	vs := Volumes(lbc.SecretNames)
	vms := VolumeMounts(lbc.SecretNames)
	// ignoring errors and trying to create controllers
	daemon := &kepi.DaemonSet{
		ObjectMeta: kapi.ObjectMeta{
			Name:      lbc.Resource.OffshootName(),
			Namespace: lbc.Resource.Namespace,
			Labels:    labelsFor(lbc.Resource.Name),
			Annotations: map[string]string{
				api.OriginAPISchema: lbc.Resource.APISchema(),
				api.OriginName:      lbc.Resource.GetName(),
			},
		},

		Spec: kepi.DaemonSetSpec{
			Selector: &unversioned.LabelSelector{
				MatchLabels: labelsFor(lbc.Resource.Name),
			},

			// pod templates.
			Template: kapi.PodTemplateSpec{
				ObjectMeta: kapi.ObjectMeta{
					Labels: labelsFor(lbc.Resource.Name),
				},
				Spec: kapi.PodSpec{
					NodeSelector: lbc.Resource.NodeSelector(),
					Containers: []kapi.Container{
						{
							Name:  "haproxy",
							Image: GetLoadbalancerImage(),
							Env: []kapi.EnvVar{
								{
									Name: "KUBE_NAMESPACE",
									ValueFrom: &kapi.EnvVarSource{
										FieldRef: &kapi.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
							Args: []string{
								"--config-map=" + lbc.Resource.OffshootName(),
								"--mount-location=" + "/etc/haproxy",
								"--boot-cmd=" + "/etc/sv/reloader/reload",
								"--v=4",
							},
							Ports:        []kapi.ContainerPort{},
							VolumeMounts: vms,
						},
					},
					Volumes: vs,
					SecurityContext: &kapi.PodSecurityContext{
						HostNetwork: true,
					},
				},
			},
		},
	}

	// adding tcp ports to pod template
	for _, port := range lbc.Ports {
		p := kapi.ContainerPort{
			Name:          "tcp-" + strconv.Itoa(port),
			Protocol:      "TCP",
			ContainerPort: int32(port),
			HostPort:      int32(port),
		}
		daemon.Spec.Template.Spec.Containers[0].Ports = append(daemon.Spec.Template.Spec.Containers[0].Ports, p)
	}

	if lbc.Parsed.Stats {
		daemon.Spec.Template.Spec.Containers[0].Ports = append(daemon.Spec.Template.Spec.Containers[0].Ports, kapi.ContainerPort{
			Name:          "stats",
			Protocol:      "TCP",
			ContainerPort: int32(lbc.Parsed.StatsPort),
			HostPort:      int32(lbc.Parsed.StatsPort),
		})
	}

	if ans, ok := lbc.Resource.PodsAnnotations(); ok {
		daemon.Spec.Template.Annotations = ans
	}

	log.Infoln("creating DaemonSets controller")
	dm, err := lbc.KubeClient.Extensions().DaemonSets(lbc.Resource.Namespace).Get(daemon.Name)
	if kerr.IsNotFound(err) {
		_, err := lbc.KubeClient.Extensions().DaemonSets(lbc.Resource.Namespace).Create(daemon)
		if err != nil {
			return errors.FromErr(err).Err()
		}
		return nil
	} else if err != nil {
		return errors.FromErr(err).Err()
	}

	needsUpdate := false
	if val, ok := lbc.ensureResourceAnnotations(dm.Annotations); ok {
		needsUpdate = true
		dm.Annotations = val
	}

	if !reflect.DeepEqual(dm.Spec, daemon.Spec) {
		needsUpdate = true
		dm.Spec = daemon.Spec
	}

	if needsUpdate {
		_, err = lbc.KubeClient.Extensions().DaemonSets(lbc.Resource.Namespace).Update(dm)
		if err != nil {
			return errors.FromErr(err).Err()
		}
	}
	return nil
}

func (lbc *EngressController) createNodePortSvc() error {
	log.Infoln("creating NodePort type lb")
	// creating service as type NodePort
	svc := &kapi.Service{
		ObjectMeta: kapi.ObjectMeta{
			Name:      lbc.Resource.OffshootName(),
			Namespace: lbc.Resource.Namespace,
			Annotations: map[string]string{
				api.OriginAPISchema: lbc.Resource.APISchema(),
				api.OriginName:      lbc.Resource.GetName(),
			},
		},
		Spec: kapi.ServiceSpec{
			Type:     kapi.ServiceTypeNodePort,
			Ports:    []kapi.ServicePort{},
			Selector: labelsFor(lbc.Resource.Name),
			// https://github.com/kubernetes/kubernetes/issues/33586
			// LoadBalancerSourceRanges: lbc.Config.Spec.LoadBalancerSourceRanges,
		},
	}

	// opening other tcp ports
	for _, port := range lbc.Ports {
		p := kapi.ServicePort{
			Name:       "tcp-" + strconv.Itoa(port),
			Protocol:   "TCP",
			Port:       int32(port),
			TargetPort: intstr.FromInt(port),
		}
		svc.Spec.Ports = append(svc.Spec.Ports, p)
	}

	if ans, ok := lbc.Resource.ServiceAnnotations(lbc.ProviderName); ok {
		for k, v := range ans {
			svc.Annotations[k] = v
		}
	}

	if lbc.ProviderName == "aws" && lbc.Resource.KeepSourceIP() {
		// ref: https://github.com/kubernetes/kubernetes/blob/release-1.5/pkg/cloudprovider/providers/aws/aws.go#L79
		svc.Annotations["service.beta.kubernetes.io/aws-load-balancer-proxy-protocol"] = "*"
	}

	s, err := lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Get(svc.Name)
	if kerr.IsNotFound(err) {
		svc, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Create(svc)
		if err != nil {
			return errors.FromErr(err).Err()
		}
		return nil
	} else if err != nil {
		return errors.FromErr(err).Err()
	}

	needsUpdate := false
	if val, ok := lbc.ensureResourceAnnotations(s.Annotations); ok {
		s.Annotations = val
		needsUpdate = true
	}

	if isServicePortChanged(s.Spec.Ports, svc.Spec.Ports) {
		needsUpdate = true
		s.Spec.Ports = svc.Spec.Ports
	}

	if needsUpdate {
		_, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Update(s)
		if err != nil {
			return errors.FromErr(err).Err()
		}
	}
	return nil
}

func (lbc *EngressController) createNodePortPods() error {
	log.Infoln("creating NodePort deployment")
	vs := Volumes(lbc.SecretNames)
	vms := VolumeMounts(lbc.SecretNames)
	// ignoring errors and trying to create controllers
	deployment := &kepi.Deployment{
		ObjectMeta: kapi.ObjectMeta{
			Name:      lbc.Resource.OffshootName(),
			Namespace: lbc.Resource.Namespace,
			Labels:    labelsFor(lbc.Resource.Name),
			Annotations: map[string]string{
				api.OriginAPISchema: lbc.Resource.APISchema(),
				api.OriginName:      lbc.Resource.GetName(),
			},
		},

		Spec: kepi.DeploymentSpec{
			Replicas: lbc.Resource.Replicas(),
			Selector: &unversioned.LabelSelector{
				MatchLabels: labelsFor(lbc.Resource.Name),
			},
			// pod templates.
			Template: kapi.PodTemplateSpec{
				ObjectMeta: kapi.ObjectMeta{
					Labels: labelsFor(lbc.Resource.Name),
				},

				Spec: kapi.PodSpec{
					NodeSelector: lbc.Resource.NodeSelector(),
					Containers: []kapi.Container{
						{
							Name:  "haproxy",
							Image: GetLoadbalancerImage(),
							Env: []kapi.EnvVar{
								{
									Name: "KUBE_NAMESPACE",
									ValueFrom: &kapi.EnvVarSource{
										FieldRef: &kapi.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
							Args: []string{
								"--config-map=" + lbc.Resource.OffshootName(),
								"--mount-location=" + "/etc/haproxy",
								"--boot-cmd=" + "/etc/sv/reloader/reload",
								"--v=4",
							},
							Ports:        []kapi.ContainerPort{},
							VolumeMounts: vms,
						},
					},
					Volumes: vs,
				},
			},
		},
	}

	// adding tcp ports to pod template
	for _, port := range lbc.Ports {
		p := kapi.ContainerPort{
			Name:          "tcp-" + strconv.Itoa(port),
			Protocol:      "TCP",
			ContainerPort: int32(port),
		}
		deployment.Spec.Template.Spec.Containers[0].Ports = append(deployment.Spec.Template.Spec.Containers[0].Ports, p)
	}

	if lbc.Parsed.Stats {
		deployment.Spec.Template.Spec.Containers[0].Ports = append(deployment.Spec.Template.Spec.Containers[0].Ports, kapi.ContainerPort{
			Name:          "stats",
			Protocol:      "TCP",
			ContainerPort: int32(lbc.Parsed.StatsPort),
			HostPort:      int32(lbc.Parsed.StatsPort),
		})
	}

	if ans, ok := lbc.Resource.PodsAnnotations(); ok {
		deployment.Spec.Template.Annotations = ans
	}

	dpl, err := lbc.KubeClient.Extensions().Deployments(lbc.Resource.Namespace).Get(deployment.Name)
	if kerr.IsNotFound(err) {
		_, err := lbc.KubeClient.Extensions().Deployments(lbc.Resource.Namespace).Create(deployment)
		if err != nil {
			return errors.FromErr(err).Err()
		}
		return nil
	} else if err != nil {
		return errors.FromErr(err).Err()
	}

	needsUpdate := false
	if val, ok := lbc.ensureResourceAnnotations(dpl.Annotations); ok {
		needsUpdate = true
		dpl.Annotations = val
	}

	if !reflect.DeepEqual(dpl.Spec, deployment.Spec) {
		needsUpdate = true
		dpl.Spec = deployment.Spec
	}

	if needsUpdate {
		_, err = lbc.KubeClient.Extensions().Deployments(lbc.Resource.Namespace).Update(dpl)
		if err != nil {
			return errors.FromErr(err).Err()
		}
	}
	return nil
}

func (lbc *EngressController) createLoadBalancerSvc() error {
	log.Infoln("creating LoadBalancer type lb")
	// creating service as typeLoadBalancer
	svc := &kapi.Service{
		ObjectMeta: kapi.ObjectMeta{
			Name:      lbc.Resource.OffshootName(),
			Namespace: lbc.Resource.Namespace,
			Annotations: map[string]string{
				api.OriginAPISchema: lbc.Resource.APISchema(),
				api.OriginName:      lbc.Resource.GetName(),
			},
		},
		Spec: kapi.ServiceSpec{
			Type:                     kapi.ServiceTypeLoadBalancer,
			Ports:                    []kapi.ServicePort{},
			Selector:                 labelsFor(lbc.Resource.Name),
			LoadBalancerSourceRanges: lbc.Resource.Spec.LoadBalancerSourceRanges,
		},
	}

	// opening other tcp ports
	for _, port := range lbc.Ports {
		p := kapi.ServicePort{
			Name:       "tcp-" + strconv.Itoa(port),
			Protocol:   "TCP",
			Port:       int32(port),
			TargetPort: intstr.FromInt(port),
		}
		svc.Spec.Ports = append(svc.Spec.Ports, p)
	}

	if ans, ok := lbc.Resource.ServiceAnnotations(lbc.ProviderName); ok {
		for k, v := range ans {
			svc.Annotations[k] = v
		}
	}

	switch lbc.ProviderName {
	case "gce", "gke":
		if ip := lbc.Resource.LoadBalancerIP(); ip != nil {
			svc.Spec.LoadBalancerIP = ip.String()
		}
	}

	s, err := lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Get(svc.Name)
	if kerr.IsNotFound(err) {
		svc, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Create(svc)
		if err != nil {
			return errors.FromErr(err).Err()
		}
		return nil
	} else if err != nil {
		return errors.FromErr(err).Err()
	}

	needsUpdate := false
	if val, ok := lbc.ensureResourceAnnotations(s.Annotations); ok {
		s.Annotations = val
		needsUpdate = true
	}

	if isServicePortChanged(s.Spec.Ports, svc.Spec.Ports) {
		needsUpdate = true
		s.Spec.Ports = svc.Spec.Ports
	}

	if needsUpdate {
		_, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Update(s)
		if err != nil {
			return errors.FromErr(err).Err()
		}
	}
	return nil
}

func (lbc *EngressController) ensureStatsService() {
	svc := &kapi.Service{
		ObjectMeta: kapi.ObjectMeta{
			Name:      lbc.Resource.StatsServiceName(),
			Namespace: lbc.Resource.Namespace,
			Annotations: map[string]string{
				api.OriginAPISchema: lbc.Resource.APISchema(),
				api.OriginName:      lbc.Resource.GetName(),
			},
		},
		Spec: kapi.ServiceSpec{
			Ports: []kapi.ServicePort{
				{

					Name:       "stats",
					Protocol:   "TCP",
					Port:       int32(lbc.Parsed.StatsPort),
					TargetPort: intstr.FromInt(lbc.Parsed.StatsPort),
				},
			},
			Selector: labelsFor(lbc.Resource.Name),
		},
	}

	s, err := lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Get(lbc.Resource.StatsServiceName())
	if kerr.IsNotFound(err) {
		_, err := lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Create(svc)
		if err != nil {
			log.Errorln("Failed to create Stats Service", err)
		}
		return
	} else if err != nil {
		log.Errorln(err)
		return
	}

	needsUpdate := false
	if val, ok := lbc.ensureResourceAnnotations(svc.Annotations); ok {
		needsUpdate = true
		svc.Annotations = val
	}

	if isServicePortChanged(s.Spec.Ports, svc.Spec.Ports) {
		needsUpdate = true
		s.Spec.Ports = svc.Spec.Ports
	}

	if !reflect.DeepEqual(svc.Spec.Selector, labelsFor(lbc.Resource.Name)) {
		needsUpdate = true
		svc.Spec.Selector = labelsFor(lbc.Resource.Name)
	}

	if needsUpdate {
		_, err = lbc.KubeClient.Core().Services(lbc.Resource.Namespace).Update(s)
		if err != nil {
			log.Errorln("Failed to update Stats Service", err)
		}
	}
}

func (lbc *EngressController) updateStatus() error {
	var statuses []kapi.LoadBalancerIngress

	switch lbc.Resource.LBType() {
	case api.LBTypeLoadBalancer:
		for i := 0; i < 50; i++ {
			time.Sleep(time.Second * 10)
			if svc, err := lbc.KubeClient.Core().
				Services(lbc.Resource.Namespace).
				Get(lbc.Resource.OffshootName()); err == nil {
				if len(svc.Status.LoadBalancer.Ingress) >= 1 {
					statuses = svc.Status.LoadBalancer.Ingress
					break
				}
			}
		}
		// TODO @sadlil consider adding node ip in status for hostport/nodeport mode
	}

	if len(statuses) > 0 {
		if lbc.Resource.APISchema() == api.APISchemaIngress {
			ing, err := lbc.KubeClient.Extensions().Ingresses(lbc.Resource.Namespace).Get(lbc.Resource.Name)
			if err != nil {
				return errors.FromErr(err).Err()
			}
			ing.Status.LoadBalancer.Ingress = statuses
			_, err = lbc.KubeClient.Extensions().Ingresses(lbc.Resource.Namespace).Update(ing)
			if err != nil {
				return errors.FromErr(err).Err()
			}
		} else {
			ing, err := lbc.ExtClient.Ingress(lbc.Resource.Namespace).Get(lbc.Resource.Name)
			if err != nil {
				return errors.FromErr(err).Err()
			}
			ing.Status.LoadBalancer.Ingress = statuses
			_, err = lbc.ExtClient.Ingress(lbc.Resource.Namespace).Update(ing)
			if err != nil {
				return errors.FromErr(err).Err()
			}
		}
	}
	return nil
}

func (lbc *EngressController) ensureResourceAnnotations(annotation map[string]string) (map[string]string, bool) {
	needsUpdate := false

	// Copy the given map to avoid updating the original annotations
	ret := annotation
	if ret == nil {
		ret = make(map[string]string)
	}

	if val := ret[api.OriginAPISchema]; val != lbc.Resource.APISchema() {
		needsUpdate = true
		ret[api.OriginAPISchema] = lbc.Resource.APISchema()
	}

	if val := ret[api.OriginName]; val != lbc.Resource.GetName() {
		needsUpdate = true
		ret[api.OriginName] = lbc.Resource.GetName()
	}
	return ret, needsUpdate
}

func labelsFor(name string) map[string]string {
	return map[string]string{
		"appType":     "ext-applbc-" + name,
		"type":        "ext-lbc-" + name,
		"target":      "eng-" + name,
		"meta":        "eng-" + name + "-applbc",
		"engressName": name,
	}
}

func Volumes(secretNames []string) []kapi.Volume {
	skipper := make(map[string]bool)
	vs := make([]kapi.Volume, 0)
	for _, s := range secretNames {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if _, ok := skipper[s+"-secret-volume"]; ok {
			continue
		}
		skipper[s+"-secret-volume"] = true
		sVolume := kapi.Volume{
			Name: s + "-secret-volume",
			VolumeSource: kapi.VolumeSource{
				Secret: &kapi.SecretVolumeSource{
					SecretName: s,
				},
			},
		}
		vs = append(vs, sVolume)
	}
	return vs
}

func VolumeMounts(secretNames []string) []kapi.VolumeMount {
	skipper := make(map[string]bool)
	ms := make([]kapi.VolumeMount, 0)
	for _, s := range secretNames {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if _, ok := skipper[s+"-secret-volume"]; ok {
			continue
		}
		skipper[s+"-secret-volume"] = true
		sMount := kapi.VolumeMount{
			Name:      s + "-secret-volume",
			MountPath: "/srv/haproxy/secrets/" + s,
		}
		ms = append(ms, sMount)
	}
	return ms
}

func isServicePortChanged(oldPorts, newPorts []kapi.ServicePort) bool {
	// Check if any port changed
	ports := make(map[int32]bool)
	for _, port := range oldPorts {
		// We only use TCP protocol so ports are unique for our scenario
		ports[port.Port] = true
	}

	for _, port := range newPorts {
		if _, ok := ports[port.Port]; !ok {
			return true
		}
	}
	return false
}
