vcl 4.0;

import std;
import directors;

probe healthcheck {
  .url = "/";
  .timeout = 2s;
  .window = 5;
  .threshold = 3;
  .interval = 5s;
}

backend ws01 { .probe=healthcheck; .host = "127.0.0.1"; .port="80"; .first_byte_timeout=2s; }
backend ws02 { .probe=healthcheck; .host = "127.0.0.1"; .port="81"; .first_byte_timeout=2s; }
backend h2o { .probe=healthcheck; .host = "127.0.0.1"; .port="8080"; .first_byte_timeout=2s; }

acl purge {
    "127.0.0.1";
}

sub vcl_init {
  new ws_hash = directors.hash();
  ws_hash.add_backend(ws01, 1.0);
  ws_hash.add_backend(ws02, 1.0);
  ws_hash.add_backend(h2o, 1.0);
}

sub vcl_recv {
    set req.backend_hint = ws_hash.backend(req.url + ":" + req.http.host);

    # [POST]/purgeでパージ
    if (req.url ~ "(\?|&)purge=1" && client.ip !~ purge) {
        if (req.method != "PURGE") {
            return (synth(405, "Method not allowed"));
        }
        ban("obj.http.X-HOST ~ "+ req.http.host + " && obj.http.X-URL ~ " + regsub(req.url,"\?.*$",""));
        return (synth(200, "Purged"));
    }

    # GET/HEAD以外弾く
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf|flv)$") {
            unset req.http.Accept-Encoding;
        } elsif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } elsif (req.http.Accept-Encoding ~ "deflate" && req.http.user-agent !~ "MSIE") {
            set req.http.Accept-Encoding = "deflate";
        } else {
            unset req.http.Accept-Encoding;
        }
    }

    std.collect(req.http.Cookie);

    return (hash);
}

sub vcl_hash {
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }

    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
}

sub vcl_backend_response {
    if (beresp.status > 400) {
        set beresp.ttl = 1d;
    }

    set beresp.grace = 1m;
    set beresp.keep = 20m;
    return (deliver);
}

sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
}

sub vcl_hit {
    if (obj.ttl >= 0s) {
        return (deliver);
    }

    if (std.healthy(req.backend_hint)) {
        if (obj.ttl + 60s > 0s) {
            # TTLが切れてgraceタイムに突入してる場合
            set req.http.grace = "healthy server";
            return (deliver);
        } else {
            # TTLもgraceも切れた場合
            return (pass);
        }
    } else {
        set req.http.grace = "unhealthy server";
        return (deliver);
    }
}