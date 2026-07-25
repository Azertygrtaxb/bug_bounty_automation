"""Paramètres de requête VOLATILES — CONNAISSANCE, retirée du hash de dédup.

Un même endpoint compté plusieurs fois vient de paramètres transients
(session, tracking, jeton anti-rejeu de fédération, cache-buster) qui varient à
chaque requête. On les retire AVANT de calculer hash_dedup pour que les
variantes du même endpoint fusionnent.

>>> Éditable : ajoute ici tout paramètre transient qui gonfle les doublons.

NE JAMAIS y mettre un paramètre porteur d'identité (id, customerId, contractId,
cat, ...) : ceux-là distinguent de VRAIS endpoints différents.
"""
VOLATILE_PARAMS = {
    # Fédération / SSO transient (WS-Federation, SAML relay)
    "tabid", "wct", "wctx", "wa", "wreply", "wtrealm", "wfresh", "relaystate",
    # Bruit pur : langue d'affichage (fr/en) — même endpoint. (PAS sourceURL :
    # une valeur de redirection différente = un test d'open-redirect distinct.)
    "displaylang",
    # Session
    "sid", "sessionid", "phpsessid", "jsessionid", "aspsessionid", "asp.net_sessionid",
    # Anti-CSRF / anti-rejeu transient
    "csrf", "csrftoken", "requestverificationtoken", "nonce",
    # Tracking marketing
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid",
    # Cache-busting / horodatage
    "_", "cb", "cachebuster", "nocache", "ts", "timestamp", "rnd", "random",
}

# Jetons-placeholder injectés par le crawler (katana/jsluice) comme valeurs de
# param : ce ne sont PAS de vraies valeurs. Traités comme vide (dédup + scoring).
# >>> Éditable. Comparaison en minuscules.
PLACEHOLDERS = {
    "expr", "fuzz", "test", "xxx", "placeholder", "value", "val", "string",
    "example", "sample", "dummy", "null", "none", "undefined", "todo",
}
