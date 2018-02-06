#### Based on github.com/kubernetes-incubator/bootkube

##### Hack / Dev multi-node build

**Note: All scripts are assumed to run from this directory.**

##### Quickstart

This will generate the default assets in the `cluster` directory and launch multi-node self-hosted gfs cluster with loadbalancer exposed on host VM.

Assets with template options are applied from the `templates/` directory
Assets not auto-generated by bootkube are in the `manifests/` directory

A load balancer node lb0 VM is added with the node label and role to
support a scheduling `manifests/loadbalancer-daemonset.yaml` and
`manifests/loadbalancer-clusterrole.yaml`

The manifests include

- heapster-controller.yaml
- kubernetes-dashboard-lb.yaml
- kubernetes-dashboard.yaml
- loadbalancer-clusterrole.yaml
- loadbalancer-daemonset.yaml

Templates applied using local configuration options include

- calico.yaml.tmpl
- deployment-ssh-jump-server.yaml.tmpl
- kube-flannel.yaml.tmpl
- kube-proxy.yaml.tmpl
- kubernetes-dashboard-certs.yaml.tmpl
- pod-checkpointer.yaml.tmpl
- user-data.tmpl

If adding the dashboard, create tls-gen using tls-gen script, if
needed run the script to create the binary

- An script for processing the deployment jump server template
  - bin/deployment-ssh-jump-server.sh

- A script to create the binary used to generate dashboard
  certificates
  - bin/dashboard-tls-gen-script

The bootkube-up-gfs stands up a vagrant cluster with a loadbalancer,
dashboard and certificates.

```
./bootkube-up-gfs
```

Now with the default configuration the lb0 VM will expose loadbalancer
items from the ip address specified in the service for example

- [ ] kubernetes-dashboard.yaml

```
# ------------------------- Service ------------------------- #
---
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard-lb
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
spec:
  selector:
    k8s-app: kubernetes-dashboard
  ports:
  - port: 443
    targetPort: 8443
    name: kubernetes-dashboard
  loadBalancerIP: 192.168.0.251
  type: LoadBalancer

```
A jump ssh service like the one in the template

- [ ] deployment-ssh-jump-server.yaml.tmpl

```
# ------------------------- Service ------------------------- #
---
apiVersion: v1
kind: Service
metadata:
  name: {{.Appl}}-{{.Release}}
  labels:
    app: {{.Appl}}-{{.Release}}
spec:
  ports:
  - port: 2222
    targetPort: 22
    name: {{.Appl}}
  loadBalancerIP: {{.LoadBalancerIP}}
  type: LoadBalancer
  selector:
    name: {{.Appl}}-{{.Release}}
```

## Cleaning up

To stop the running cluster and remove generated assets, run:

```
vagrant destroy -f
rm -rf cluster
```

##### General Modifications from the default bootkube project

Out of the box boot kube had 2 types of nodes
- enable role for worker nodes
- enable role for mastre nodes

After some template and script changes it supports storage and load
balancer roles
- enable role for gfs nodes
  - node-role.kubernetes.io/storage,gluster.io/server=true
- enable role for a loadbalancer
  - node-role.kubernetes.io/loadbalancer

Tolerations are required for system pods that run across nodes to
schedule on lb0 the loadbalancer node.

      tolerations:
        # Allow the pod to run on master nodes
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
        # Allow the pod to run on loadbalancer nodes
        - key: node-role.kubernetes.io/loadbalancer
          effect: NoSchedule

Force scheduling load balancer only on
node-role.kubernetes.io/loadbalancer labeled node and allow scheduling
with toleration

```
      tolerations:
        - key: node-role.kubernetes.io/loadbalancer
          operator: Exists
          effect: NoSchedule
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-role.kubernetes.io/loadbalancer
                operator: Exists

```

Taint the load balancer node to repel (give scheduling anti affinity to all but those pods with manifests)

Label the node for scheduling affinity, taint for generic anti affinity

```
    .
    .
    .
          --node-labels=node-role.kubernetes.io/loadbalancer=primary \
          --register-with-taints=node-role.kubernetes.io/loadbalancer=:NoSchedule \
    .
    .

```

Example dump formatted node info with kubectl
```
kubectl get no -o go-template  --template='{{ range .items }}{{"\n"}}{{ .metadata.name }}{{range $k,$v := .metadata.labels }}{{"\n"}}{{ printf "  %-32s" $k }}{{ if $v }}{{ printf ": %s" $v }}{{end}}{{end}}{{end}}{{"\n\n"}}'
```

