.. und noch eine kleine PHP-Klasse, welche gerade bei Netzwerkgeräten (Procurve Switches) jegliche Informationen abgreifen und auch setzen kann.
Die Klasse ist in der Lage, die korrekten Credentials für ein Device „durchzuprobieren“ und somit auch funktional in „Legacy“-Umgebungen.

Grundlegender Zugriff:

$z = new MySNMP();
$z->checkCredentials();
$z = new MySNMP();
$z->checkCredentials();

… nun werden alle definierten Credentials „durchprobiert“ und, falls ein Zugriff stattfinden kann, die korrekten in den Variablen …


STRING: $z->version
STRING: $z->community           (für v1/v2)
STRING: $z->sec_name            (für v3)
STRING: $z->auth_passphrase     (für v3)
STRING: $z->priv_passphrase     (für v3)
STRING: $z->version
STRING: $z->community           (für v1/v2)
STRING: $z->sec_name            (für v3)
STRING: $z->auth_passphrase     (für v3)
STRING: $z->priv_passphrase     (für v3)

… abgelegt.
