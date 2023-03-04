#!/usr/bin/env bash

#
# .-'_.---._'-.
# ||####|(__)||   Protect your secrets, protect your business.
#   \\()|##//       Secure your sensitive data with Aegis.
#    \\ |#//                    <aegis.ist>
#     .\_/.
#

kubectl apply -f ./k8s/Namespace.yaml
kubectl apply -f ./k8s/Role.yaml

if kubectl get secret -n aegis-system | grep safe-age-key; then
  echo "!!! The secret 'safe-age-key' already exists; not going to override it."
  echo "!!! If you want to modify it, make sure you back it up first."
else
  kubectl apply -f ./k8s/Secret.yaml
fi

kubectl apply -f ./k8s/ServiceAccount.yaml
kubectl apply -f ./k8s/Identity.yaml
kubectl apply -k ./k8s
kubectl apply -f ./k8s/Service.yaml
