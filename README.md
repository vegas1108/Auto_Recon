# Check_auto

CLI Python pour lancer une base de recon terminal sur une cible HTB-like, sauvegarder les sorties `nmap` et résumer rapidement si la machine ressemble à du `windows`, du `linux` ou à un hôte avec indicateurs Active Directory.

Le périmètre de cette première version reste volontairement limité aux scans d'inventaire et au parsing de résultats. Je n'ai pas inclus l'automatisation des parties offensives de la checklist comme le password spray, `kerbrute`, `netexec`, l'énumération authentifiée ou d'autres actions à impact.

## Lancer

```bash
python3 recon.py 10.10.11.10
```

Exemples utiles :

```bash
python3 recon.py 10.10.11.10 --os windows
python3 recon.py 10.10.11.10 --os linux --min-rate 1500
python3 recon.py 10.10.11.10 --dry-run
python3 recon.py 10.10.11.10 --no-color
python3 recon.py 10.10.11.10 --command-timeout 120
python3 recon.py 10.10.11.10 --fast
python3 recon.py 10.10.11.10 --html-report
python3 recon.py 10.10.11.10 --keep-logs
python3 recon.py 10.10.11.10 --ad yes --domain htb.local --dc-ip 10.10.11.10
python3 recon.py 10.10.11.10 --ad yes --domain htb.local --username user --password pass
```

## Ce que fait l'outil

- affiche une bannière ASCII `vegas`
- affiche une sortie terminal structurée avec couleurs, sections, commandes et statut final
- genere par defaut un seul fichier final `report_<target>_<date>.txt`, directement dans le dossier de sortie
- supprime les logs intermediaires apres parsing, sauf avec `--keep-logs`
- peut aussi generer `report.html` avec `--html-report`
- crée un dossier de session dans `runs/`
- lance un scan TCP complet `nmap -p- -Pn`
- parse les ports ouverts
- attend 5 secondes puis lance `nmap -sV -sC` sur les ports trouvés
- attend 5 secondes puis lance `nmap --script vuln`
- tente d'extraire les indices de domaine et de DC depuis les sorties
- si AD est détecté ou forcé avec `--ad yes`, lance les commandes AD de la checklist selon les infos disponibles
- si `--username` et `--password` sont fournis, lance aussi les commandes authentifiées
- avec creds, teste aussi RPC authentifié via `rpcclient` (`enumdomusers`, `querydispinfo`, `enumdomgroups`)
- met en evidence les shares non standards, en separant `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`, etc.
- met en evidence les credentials potentiels trouves dans les logs, shares crawles et sorties GPP (`password`, `cpassword`, `pwd`, `secret`, etc.)
- liste recursivement les shares non standards et met en evidence les fichiers interessants sans les telecharger
- affiche une alerte dediee si des indices ADCS / Certificate Services sont trouves (`ADCS`, `CertSrv`, `CertEnroll`, `Certificate Authority`, etc.)
- evite les doublons: si un outil trouve deja des users, shares ou groupes, les modules equivalents suivants sont marques `skipped`
- met en avant les signaux AD importants comme Kerberoast, ASREP roast, delegation et groupes privilegies
- ne fait plus de pauses fixes entre les scans
- `--fast` garde uniquement les checks AD rapides et high-signal
- utilise `enum4linux-ng` pour les étapes enum4linux
- produit `summary.txt` et `summary.json`

Par défaut, la sortie complète des outils n'est pas affichée en live. Le terminal montre une progression courte puis le résumé final. Pour afficher les commandes :

```bash
python3 recon.py 10.10.11.10 --show-commands
```

Pour voir toute la sortie brute :

```bash
python3 recon.py 10.10.11.10 --verbose-output
```

## Options AD

```bash
python3 recon.py 10.10.11.10 --ad yes --domain htb.local --dc-ip 10.10.11.10
```

Avec creds :

```bash
python3 recon.py 10.10.11.10 --ad yes --domain htb.local -u user -p 'pass'
```

User enum Kerberos si tu fournis une wordlist :

```bash
python3 recon.py 10.10.11.10 --ad yes --domain htb.local --user-wordlist /opt/jsmith.txt
```

Le spray ne part jamais par défaut. Il faut l'activer explicitement :

```bash
python3 recon.py 10.10.11.10 --ad yes --domain htb.local --user-wordlist users.txt --enable-spray --spray-password 'Password123!'
```

## Fichiers générés

Par defaut, chaque session conserve seulement un fichier directement dans le dossier de sortie :

- `report_<target>_<date>.txt`

Avec `--html-report`, elle conserve aussi :

- `report_<target>_<date>.html`

Avec `--keep-logs`, elle conserve aussi les sorties brutes des commandes.

## Notes

- dépendance requise : `nmap`
- l'outil fonctionne uniquement en terminal
- si `--os auto` est utilisé, la détection repose sur des heuristiques simples à partir des ports et bannières
