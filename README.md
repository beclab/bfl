# Backend For Launcher (BFL)
[![](https://github.com/beclab/bfl/actions/workflows/build_main.yml/badge.svg?branch=main)](https://github.com/beclab/bfl/actions/workflows/build_main.yml)

## apiserver
Provides some APIs for the launcher apps. 

### How to build
```sh
make bfl
```

## ingress
User's desktop and apps ingress controller. When the user installs or uninstalls an app, the controller will create or delete a domain automatically.
### How to build
```sh
make bfl-ingress
```

## FRPC
A FRPC agent, which acts as a controller to keep the FRPC's configuration reconciled with the ingress
