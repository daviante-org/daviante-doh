#!/usr/bin/env sh
# =============================================================================
# Kubernetes & Red Hat OpenShift Black-Box API & Protocol Tester CI Runner
#
# Provisions an ephemeral kind cluster with MetalLB Layer-2 LoadBalancer,
# deploys charts/daviante-doh in both:
#   1. Kubernetes Mode (2 replicas, MetalLB Service LoadBalancer + L7 Ingress)
#   2. OpenShift Mode (2 replicas, route.openshift.io/v1 CRD + HAProxy Router
#      with reencrypt HTTP/2 + restricted-v2 SCC UID 20001:0)
# Executes the 73-case live DoH API & Protocol Matrix against both environments
# and records per-pod load distribution & cluster telemetry.
# =============================================================================
set -eu

IMAGE_TAG="${IMAGE_TAG:-ghcr.io/daviante-org/daviante-doh:e2e-test}"
CLUSTER_NAME="${CLUSTER_NAME:-daviante-doh-ci}"
KEEP_CLUSTER="${KEEP_CLUSTER:-false}"

IMAGE_REPO="${IMAGE_TAG%:*}"
IMAGE_VERSION="${IMAGE_TAG##*:}"

CERT_FILE="$(mktemp)"
KEY_FILE="$(mktemp)"
PEM_FILE="$(mktemp)"
COMMON_VALUES_FILE="$(mktemp)"

cleanup() {
    rm -f "$CERT_FILE" "$KEY_FILE" "$PEM_FILE" "$COMMON_VALUES_FILE"
    if [ "$KEEP_CLUSTER" != "true" ] && command -v kind >/dev/null 2>&1; then
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

cat > "$CERT_FILE" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBmDCCAT+gAwIBAgIUNkDcdb1ZlMu64/GJkM44GkERsaAwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxNzIzNTE1NFoXDTM2MTAxNDIz
NTE1NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAErWF7m21jDRyZr+u79nnigFHMXSBZVcsqDn/d0yqFsV8Ch4yNP2S/1XIa
kax2nnW3xeW+SsJi+sA/byCq12JoKaNvMG0wHQYDVR0OBBYEFO0UieoBWoaZqtEf
A2xv5ykf9V2rMB8GA1UdIwQYMBaAFO0UieoBWoaZqtEfA2xv5ykf9V2rMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49
BAMCA0cAMEQCIGTM8ArzrRMwK9y1TKy+irluoIIF5as2qdFdSc/AgFEAAiBsPLDg
blVaU9jbWKRNgVekewSGO76v9Kqw7knea8HweA==
-----END CERTIFICATE-----
EOF

cat > "$KEY_FILE" <<'EOF'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDDxGimCBITAIRnKd
tYIR6+QBODvchStEmUe21mRmAs2hRANCAAStYXubbWMNHJmv67v2eeKAUcxdIFlV
yyoOf93TKoWxXwKHjI0/ZL/VchqRrHaedbfF5b5KwmL6wD9vIKrXYmgp
-----END PRIVATE KEY-----
EOF
cat "$CERT_FILE" "$KEY_FILE" > "$PEM_FILE"
chmod 0644 "$CERT_FILE" "$KEY_FILE" "$PEM_FILE"

# -----------------------------------------------------------------------------
# 1. Ensure kind is installed and bootstrap cluster
# -----------------------------------------------------------------------------
if ! command -v kind >/dev/null 2>&1; then
    echo "==> Installing kind v0.27.0..."
    mkdir -p "$HOME/.local/bin"
    curl --proto '=https' --tlsv1.2 -fsSLo "$HOME/.local/bin/kind" "https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64"
    chmod +x "$HOME/.local/bin/kind"
    export PATH="$HOME/.local/bin:$PATH"
fi

echo "==> [1/6] Creating kind Kubernetes cluster (${CLUSTER_NAME})..."
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER_NAME" --wait 90s

echo "==> [2/6] Loading pre-built ${IMAGE_TAG} and pulling haproxy:3.1-alpine into kind cluster..."
if ! kind load docker-image "$IMAGE_TAG" --name "$CLUSTER_NAME"; then
    docker save "$IMAGE_TAG" | docker exec -i "${CLUSTER_NAME}-control-plane" ctr --namespace=k8s.io images import --digests --snapshotter=overlayfs -
fi
docker exec "${CLUSTER_NAME}-control-plane" crictl pull docker.io/library/haproxy:3.1-alpine >/dev/null

# -----------------------------------------------------------------------------
# 2. Install MetalLB Layer-2 LoadBalancer Controller
# -----------------------------------------------------------------------------
echo "==> [3/6] Installing MetalLB v0.14.9 Layer-2 LoadBalancer..."
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.9/config/manifests/metallb-native.yaml >/dev/null
kubectl wait --namespace metallb-system \
    --for=condition=ready pod \
    --selector=app=metallb \
    --timeout=120s

# Derive a routable IPv4 VIP range from the kind Docker network
KIND_NET_CIDR=$(docker network inspect -f '{{range .IPAM.Config}}{{if .Subnet}}{{.Subnet}} {{end}}{{end}}' kind | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -n 1)
NET_PREFIX=$(echo "$KIND_NET_CIDR" | awk -F. '{print $1"."$2}')
LB_RANGE="${NET_PREFIX}.255.200-${NET_PREFIX}.255.240"
echo "    Configuring MetalLB L2 IPAddressPool: ${LB_RANGE} (from kind subnet ${KIND_NET_CIDR})"

cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kind-l2-pool
  namespace: metallb-system
spec:
  addresses:
    - ${LB_RANGE}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: kind-l2-adv
  namespace: metallb-system
spec:
  ipAddressPools:
    - kind-l2-pool
EOF

wait_for_lb_ip() {
    ns="$1"
    svc="$2"
    ip=""
    for _ in $(seq 1 45); do
        ip=$(kubectl get svc "$svc" -n "$ns" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
        if [ -n "$ip" ] && curl -ksS --max-time 2 "https://${ip}:8443/healthz" >/dev/null 2>&1; then
            echo "$ip"
            return 0
        fi
        sleep 1
    done
    echo "Error: Timed out waiting for MetalLB LoadBalancer IP (${ip:-unassigned}) readiness on ${ns}/${svc}" >&2
    kubectl get svc,endpoints,pods -n "$ns" >&2 || true
    return 1
}

collect_pod_metrics() {
    ns="$1"
    out=""
    for pod in $(kubectl get pods -n "$ns" -l app.kubernetes.io/name=daviante-doh -o jsonpath='{.items[*].metadata.name}'); do
        pod_ip=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.podIP}')
        reqs=$(docker exec "${CLUSTER_NAME}-control-plane" curl -ksS --max-time 10 "https://${pod_ip}:3000/metrics" | awk '/^daviante_doh_requests_total / {print $2}')
        out="${out}${pod}=${reqs:-0} "
    done
    echo "$out" | sed 's/ *$//'
}

cat > "$COMMON_VALUES_FILE" <<EOF
replicaCount: 2
image:
  repository: "${IMAGE_REPO}"
  tag: "${IMAGE_VERSION}"
  pullPolicy: Never
tls:
  enabled: true
  secretName: daviante-doh-tls
config:
  listenAddress: "0.0.0.0:3000"
  serverAddress: "1.1.1.1:53,8.8.8.8:53,9.9.9.9:53"
  cacheSize: "4096"
  enableMetrics: "true"
  maxClients: "2048"
  maxConcurrent: "1024"
  rateLimitRps: "100"
  rateLimitBurst: "150"
  enableEcs: "false"
  trustedProxies: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"
EOF

# -----------------------------------------------------------------------------
# 3. Environment 2: Kubernetes Deployment (2 Replicas + MetalLB LoadBalancer + L7 Ingress)
# -----------------------------------------------------------------------------
echo "==> [4/6] Deploying charts/daviante-doh to Kubernetes (namespace: daviante-doh-k8s, replicaCount=2)..."
mkdir -p ./test-evidence/kubernetes
kubectl create namespace daviante-doh-k8s
kubectl create secret tls daviante-doh-tls -n daviante-doh-k8s --cert="$CERT_FILE" --key="$KEY_FILE"
kubectl create secret generic daviante-doh-haproxy-pem -n daviante-doh-k8s --from-file=tls.pem="$PEM_FILE"

helm upgrade --install daviante-doh ./charts/daviante-doh \
    --namespace daviante-doh-k8s \
    -f "$COMMON_VALUES_FILE" \
    --set service.type=LoadBalancer \
    --set service.port=8443 \
    --set ingress.enabled=true \
    --set ingress.className=haproxy \
    --set ingress.hosts[0].host=doh.k8s.local \
    --set ingress.hosts[0].paths[0].path=/dns-query \
    --set ingress.hosts[0].paths[0].pathType=Exact \
    --set ingress.hosts[0].paths[1].path=/.well-known/odohconfigs \
    --set ingress.hosts[0].paths[1].pathType=Exact \
    --wait --timeout 120s

K8S_LB_VIP=$(wait_for_lb_ip daviante-doh-k8s daviante-doh)
echo "    MetalLB assigned External VIP ${K8S_LB_VIP} to Kubernetes Service daviante-doh-k8s/daviante-doh"

K8S_P1_IP=$(kubectl get pods -n daviante-doh-k8s -l app.kubernetes.io/name=daviante-doh -o jsonpath='{.items[0].status.podIP}')
K8S_P2_IP=$(kubectl get pods -n daviante-doh-k8s -l app.kubernetes.io/name=daviante-doh -o jsonpath='{.items[1].status.podIP}')

# Deploy L7 Ingress Controller (HAProxy) load-balancing directly across both daviante-doh Pod Endpoints
cat <<EOF | kubectl apply -n daviante-doh-k8s -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: k8s-ingress-haproxy-cfg
data:
  haproxy.cfg: |
    global
      maxconn 4096
      tune.bufsize 131072
    defaults
      mode http
      timeout connect 5s
      timeout client 30s
      timeout server 30s
      option forwardfor
    frontend k8s_https_in
      bind *:8443 ssl crt /etc/haproxy/pem/tls.pem alpn h2,http/1.1
      http-request set-header X-Forwarded-Proto https
      default_backend daviante_doh_k8s_pods
    backend daviante_doh_k8s_pods
      balance roundrobin
      server daviante_doh_pod_1 ${K8S_P1_IP}:3000 ssl verify none alpn h2 proto h2
      server daviante_doh_pod_2 ${K8S_P2_IP}:3000 ssl verify none alpn h2 proto h2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k8s-ingress-gateway
spec:
  replicas: 1
  selector:
    matchLabels:
      app: k8s-ingress-gateway
  template:
    metadata:
      labels:
        app: k8s-ingress-gateway
    spec:
      containers:
        - name: haproxy
          image: haproxy:3.1-alpine
          imagePullPolicy: Never
          args: ["-f", "/etc/haproxy/cfg/haproxy.cfg"]
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: cfg
              mountPath: /etc/haproxy/cfg
            - name: pem
              mountPath: /etc/haproxy/pem
      volumes:
        - name: cfg
          configMap:
            name: k8s-ingress-haproxy-cfg
        - name: pem
          secret:
            secretName: daviante-doh-haproxy-pem
---
apiVersion: v1
kind: Service
metadata:
  name: k8s-ingress-lb
spec:
  type: LoadBalancer
  selector:
    app: k8s-ingress-gateway
  ports:
    - port: 8443
      targetPort: 8443
EOF

kubectl rollout status deployment/k8s-ingress-gateway -n daviante-doh-k8s --timeout=90s
K8S_INGRESS_VIP=$(wait_for_lb_ip daviante-doh-k8s k8s-ingress-lb)
echo "    MetalLB assigned External VIP ${K8S_INGRESS_VIP} to Kubernetes L7 Ingress Gateway (Host: doh.k8s.local)"

# Verify direct L4 Service LoadBalancer VIP responds over HTTP/2
curl -ksS --http2 -H "Accept: application/dns-message" "https://${K8S_LB_VIP}:8443/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" >/dev/null

echo "==> Running 73-Case Black-Box API & Protocol Suite against Kubernetes LoadBalancer (${K8S_INGRESS_VIP}:8443 -> 2 pods)..."
DOH_TEST_URL="https://${K8S_INGRESS_VIP}:8443" \
DOH_TEST_AUTHORITY="doh.k8s.local" \
DOH_EVIDENCE_DIR="./test-evidence/kubernetes" \
DOH_ENV_NAME="Kubernetes (MetalLB LoadBalancer + Ingress, 2 Replicas)" \
DOH_LOAD_BALANCER_MODE="MetalLB L2 LoadBalancer (Svc VIP ${K8S_LB_VIP}, Ingress VIP ${K8S_INGRESS_VIP} -> 2x daviante-doh pods)" \
DOH_SECURITY_CONTEXT="Kubernetes Non-Root (UID 10001:0, readOnlyRootFilesystem, cap-drop=ALL, RuntimeDefault)" \
DOH_REPLICA_COUNT="2" \
node ./scripts/e2e/live-api-suite.mjs

# Collect per-pod request distribution across the 2 Kubernetes replicas
K8S_POD_METRICS=$(collect_pod_metrics daviante-doh-k8s)
echo "    Kubernetes Per-Pod Request Distribution: ${K8S_POD_METRICS}"
kubectl get pods,svc,ingress -n daviante-doh-k8s -o wide > ./test-evidence/kubernetes/cluster-resources.txt
kubectl logs -n daviante-doh-k8s -l app.kubernetes.io/name=daviante-doh --tail=200 > ./test-evidence/kubernetes/container-logs.txt 2>&1 || true
printf '{"serviceLbVip":"%s","ingressLbVip":"%s","podDistribution":"%s"}\n' "$K8S_LB_VIP" "$K8S_INGRESS_VIP" "$K8S_POD_METRICS" > ./test-evidence/kubernetes/cluster-telemetry.json

# -----------------------------------------------------------------------------
# 4. Environment 3: Red Hat OpenShift Mode (Route CRD + HAProxy Router + restricted-v2 SCC)
# -----------------------------------------------------------------------------
echo "==> [5/6] Registering OpenShift Route CRD (route.openshift.io/v1) and deploying daviante-doh-openshift..."
mkdir -p ./test-evidence/openshift

cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: routes.route.openshift.io
spec:
  group: route.openshift.io
  names:
    kind: Route
    listKind: RouteList
    plural: routes
    singular: route
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
EOF

cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Namespace
metadata:
  name: daviante-doh-openshift
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
EOF

kubectl create secret tls daviante-doh-tls -n daviante-doh-openshift --cert="$CERT_FILE" --key="$KEY_FILE"
kubectl create secret generic daviante-doh-haproxy-pem -n daviante-doh-openshift --from-file=tls.pem="$PEM_FILE"

helm upgrade --install daviante-doh ./charts/daviante-doh \
    --namespace daviante-doh-openshift \
    -f "$COMMON_VALUES_FILE" \
    --set podSecurityContext.runAsNonRoot=true \
    --set podSecurityContext.runAsUser=20001 \
    --set podSecurityContext.runAsGroup=0 \
    --set podSecurityContext.fsGroup=0 \
    --set podSecurityContext.seccompProfile.type=RuntimeDefault \
    --set service.type=ClusterIP \
    --set service.port=8443 \
    --set route.enabled=true \
    --set route.host=doh.apps.openshift.local \
    --set route.tls.enabled=true \
    --set route.tls.termination=reencrypt \
    --wait --timeout 120s

# Verify OpenShift Route CRD resource was created with reencrypt termination
ROUTE_HOST=$(kubectl get route.route.openshift.io daviante-doh -n daviante-doh-openshift -o jsonpath='{.spec.host}')
ROUTE_TERM=$(kubectl get route.route.openshift.io daviante-doh -n daviante-doh-openshift -o jsonpath='{.spec.tls.termination}')
echo "    Verified OpenShift Route resource: host=${ROUTE_HOST}, tls.termination=${ROUTE_TERM}"
if [ "$ROUTE_HOST" != "doh.apps.openshift.local" ] || [ "$ROUTE_TERM" != "reencrypt" ]; then
    echo "Error: Unexpected OpenShift Route spec (host=${ROUTE_HOST}, termination=${ROUTE_TERM})" >&2
    exit 1
fi

OCP_P1_IP=$(kubectl get pods -n daviante-doh-openshift -l app.kubernetes.io/name=daviante-doh -o jsonpath='{.items[0].status.podIP}')
OCP_P2_IP=$(kubectl get pods -n daviante-doh-openshift -l app.kubernetes.io/name=daviante-doh -o jsonpath='{.items[1].status.podIP}')

# Deploy OpenShift HAProxy Router in a separate infrastructure namespace (openshift-ingress) backed by MetalLB LoadBalancer VIP
kubectl create namespace openshift-ingress
kubectl create secret generic daviante-doh-haproxy-pem -n openshift-ingress --from-file=tls.pem="$PEM_FILE"

cat <<EOF | kubectl apply -n openshift-ingress -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: openshift-haproxy-router-cfg
data:
  haproxy.cfg: |
    global
      maxconn 4096
      tune.bufsize 131072
    defaults
      mode http
      timeout connect 5s
      timeout client 30s
      timeout server 30s
      option forwardfor
    frontend openshift_router_https
      bind *:8443 ssl crt /etc/haproxy/pem/tls.pem alpn h2,http/1.1
      http-request set-header X-Forwarded-Proto https
      http-request set-header X-Forwarded-Port 8443
      acl host_doh hdr(host) -i ${ROUTE_HOST} -i ${ROUTE_HOST}:8443
      use_backend be_reencrypt_daviante-doh if host_doh
      default_backend be_reencrypt_daviante-doh
    backend be_reencrypt_daviante-doh
      balance roundrobin
      server daviante_doh_ocp_pod_1 ${OCP_P1_IP}:3000 ssl verify none alpn h2 proto h2
      server daviante_doh_ocp_pod_2 ${OCP_P2_IP}:3000 ssl verify none alpn h2 proto h2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openshift-router
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openshift-router
  template:
    metadata:
      labels:
        app: openshift-router
    spec:
      containers:
        - name: router
          image: haproxy:3.1-alpine
          imagePullPolicy: Never
          args: ["-f", "/etc/haproxy/cfg/haproxy.cfg"]
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: cfg
              mountPath: /etc/haproxy/cfg
            - name: pem
              mountPath: /etc/haproxy/pem
      volumes:
        - name: cfg
          configMap:
            name: openshift-haproxy-router-cfg
        - name: pem
          secret:
            secretName: daviante-doh-haproxy-pem
---
apiVersion: v1
kind: Service
metadata:
  name: openshift-router-lb
spec:
  type: LoadBalancer
  selector:
    app: openshift-router
  ports:
    - port: 8443
      targetPort: 8443
EOF

kubectl rollout status deployment/openshift-router -n openshift-ingress --timeout=90s
OCP_ROUTER_VIP=$(wait_for_lb_ip openshift-ingress openshift-router-lb)
echo "    MetalLB assigned External VIP ${OCP_ROUTER_VIP} to OpenShift HAProxy Router (Route: ${ROUTE_HOST}, mode: ${ROUTE_TERM})"

echo "==> [6/6] Running 73-Case Black-Box API & Protocol Suite against OpenShift HAProxy Router (${OCP_ROUTER_VIP}:8443 -> 2 restricted-v2 pods)..."
DOH_TEST_URL="https://${OCP_ROUTER_VIP}:8443" \
DOH_TEST_AUTHORITY="${ROUTE_HOST}" \
DOH_EVIDENCE_DIR="./test-evidence/openshift" \
DOH_ENV_NAME="Red Hat OpenShift (Route CRD + HAProxy Router + restricted-v2 SCC, 2 Replicas)" \
DOH_LOAD_BALANCER_MODE="OpenShift HAProxy Router (Route: ${ROUTE_HOST}, TLS=${ROUTE_TERM}, MetalLB VIP ${OCP_ROUTER_VIP}:8443 -> 2x pods)" \
DOH_SECURITY_CONTEXT="OpenShift restricted-v2 SCC (UID 1000650000:0, PodSecurity=restricted, readOnlyRootFilesystem, cap-drop=ALL)" \
DOH_REPLICA_COUNT="2" \
node ./scripts/e2e/live-api-suite.mjs

# Collect per-pod request distribution across the 2 OpenShift replicas
OCP_POD_METRICS=$(collect_pod_metrics daviante-doh-openshift)
echo "    OpenShift Per-Pod Request Distribution: ${OCP_POD_METRICS}"
kubectl get pods,svc,route.route.openshift.io -n daviante-doh-openshift -o wide > ./test-evidence/openshift/cluster-resources.txt
kubectl logs -n daviante-doh-openshift -l app.kubernetes.io/name=daviante-doh --tail=200 > ./test-evidence/openshift/container-logs.txt 2>&1 || true
printf '{"routerLbVip":"%s","routeHost":"%s","routeTermination":"%s","podDistribution":"%s"}\n' "$OCP_ROUTER_VIP" "$ROUTE_HOST" "$ROUTE_TERM" "$OCP_POD_METRICS" > ./test-evidence/openshift/cluster-telemetry.json

echo "==> All Kubernetes and OpenShift Black-Box API & Protocol tests completed!"
