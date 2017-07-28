{% import "makina-states/services/http/nginx/init.sls" as nginx %}

{% set cfg = opts.ms_project %}
{% set data = cfg.data %}

include:
  - makina-states.services.http.nginx

{{ nginx.virtualhost(domain=data.domain, doc_root=data.static,
                     server_aliases=data.server_aliases,
                     vhost_basename='corpus-'+cfg.name,
                     force_reload=True,
                     vh_top_source=data.nginx_upstreams,
                     vh_content_source=data.nginx_vhost,
                     cfg=cfg)}}
