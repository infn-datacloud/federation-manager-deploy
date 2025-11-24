# federation-manager-deploy

Repository with docker compose and kubernetes examples

# Docker compose

Here a schema of how the components are connected

![Containers schema](containers-schema.png)

Before starting the docker compose:
- Create a `.env` file in the top directory. 
- Create a client IAM on `https://iam.cloud.infn.it/`
- Add to the `.env` file the corresponding `CLIENT_ID` and `CLIENT_SECRET` values.
- Add to your `/etc/hosts` file the entry `127.0.0.1 fed-mgr.test.cloud.infn.it` 

To start the docker compose run from the top directory:

```bash
docker compose up -d
```
