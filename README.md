# Nginx w/ WebAuthn
[WebAuthn](https://en.wikipedia.org/wiki/WebAuthn) for [nginx](https://en.wikipedia.org/wiki/Nginx) using [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request).  Project is inspired and ported from 
[NGINX + WebAuthn for your small scale web applications](https://github.com/newhouseb/nginxwebauthn) repository.

Modify your nginx configuration as follows.  Update `server_name` and your SSL settings (WebAuthn requires SSL).

```
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate cert.pem;
    ssl_certificate_key cert.key;

    # Redirect everything that begins with /auth to the authorization server
    location /auth {
        proxy_pass http://localhost:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # If the authorization server returns 401 Unauthorized, redirect to /auth/login
    error_page 401 = @error401;
    location @error401 {
        return 302 /auth/login;
    }

    root html;
    index index.html;

    location / {
        auth_request /auth/check; # Ping /auth/check for every request, and if it returns 200 OK grant
    }
}
```

Run the ASP.NET Core application and navigate to the configured nginx site.  You should be automatically routed to `/auth/login`.

Insert your security key to register it and you will get a message that includes the public key.  Copy and paste it into the `Realms` section in the appsettings.json file.

After restarting the application and navigating to the site, you should be prompted to insert your security key to authenticate.