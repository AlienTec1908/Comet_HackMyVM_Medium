# Comet - HackMyVM (Medium)

![Comet Icon](Comet.png)

## Übersicht

*   **VM:** Comet
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Comet)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 10. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Comet_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Comet" von HackMyVM (Schwierigkeitsgrad: Medium) bot einen Pfad zur Kompromittierung, der mit Web-Enumeration begann. Ein Web-Admin-Login wurde mittels Brute-Force (unter Umgehung einer IP-basierten Blacklist durch Setzen eines HTTP-Headers) geknackt. Nach dem Login konnten Firewall-Logdateien und eine Binärdatei heruntergeladen werden. Aus diesen wurden Hinweise auf einen Benutzernamen (`Joe`) und ein Passwort-Hash (SHA-256) extrahiert. Der Hash wurde erfolgreich geknackt, was SSH-Zugriff als Benutzer `Joe` ermöglichte. Die Privilegienerweiterung zu Root erfolgte durch die Ausnutzung einer `sudo`-Regel, die die Ausführung eines Bash-Skripts erlaubte, welches eine MD5-Hash-Überprüfung durchführte. Durch Generierung einer MD5-Kollision konnte diese Prüfung umgangen und Root-Rechte erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `gobuster`
*   `nmap`
*   `nikto`
*   `wfuzz`
*   `hydra`
*   `curl`
*   `wget`
*   `cat`
*   `sort`, `uniq`
*   `strings`
*   `vi`
*   `sed`, `tr`, `echo`
*   `hashcat`
*   `ssh`
*   `file`
*   `sudo`
*   `find`
*   `python http.server`
*   `chmod`
*   `md5collgen`
*   `mv`, `md5sum`
*   Standard Linux-Befehle (`ls`, `bash`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Comet" erfolgte in diesen Schritten:

1.  **Reconnaissance & Web Enumeration:**
    *   Ziel-IP (`192.168.2.122`, Hostname `comet.hmv`) via `arp-scan` und `/etc/hosts` identifiziert.
    *   `nmap` zeigte offene Ports 22 (SSH 8.4p1) und 80 (Apache 2.4.54, Titel "CyberArray").
    *   `gobuster` und `nikto` fanden Standard-Webseiten, `/images/` (mit Directory Indexing), eine leere `ip.txt` und eine `login.php`. Nikto vermutete eine "User Online 2.0"-Anwendung wegen `ip.txt`.
    *   Fuzzing auf `login.php` mit `wfuzz` auf Parameter war erfolglos.

2.  **Initial Access (Web-Login & SSH):**
    *   Ein Brute-Force-Angriff mit `hydra` auf `login.php` für den Benutzer `admin` wurde gestartet. Es wurde ein benutzerdefinierter HTTP-Header `X-ORIGINATING-IP:test` verwendet, um eine vermutete IP-Sperre zu umgehen. Das Passwort `solitario` wurde gefunden.
    *   Nach dem Login als `admin` wurde ein Verzeichnis `/logFire/` mit zahlreichen `firewall.log.*`-Dateien entdeckt und heruntergeladen.
    *   Analyse der Logs (`cat * | sort | uniq -u`) enthüllte einen Eintrag mit dem Benutzernamen `Joe`.
    *   Aus einer heruntergeladenen Datei `firewall_update` (Herkunft nach Admin-Login) wurden mit `strings` hexadezimale Zeichenketten extrahiert, die zu einem SHA-256 Hash zusammengefügt wurden: `b8728ab81a3c3391f5f63f39da72ee89f43f9a9f429bc8cfe858f8048eaad2b1`.
    *   `hashcat` knackte diesen Hash mit `rockyou.txt` zum Passwort `prettywoman`.
    *   Erfolgreicher SSH-Login als `joe` mit dem Passwort `prettywoman`.
    *   Die User-Flag wurde aus `/home/joe/user.txt` gelesen.

3.  **Privilege Escalation (MD5 Collision & Sudo):**
    *   Im Home-Verzeichnis von `joe` befand sich ein für alle ausführbares Bash-Skript `coll`, das `root` gehörte.
    *   `sudo -l` für `joe` zeigte: `(ALL : ALL) NOPASSWD: /bin/bash /home/joe/coll`.
    *   Das Skript `coll` (Inhalt nicht direkt gezeigt, aber impliziert) führte eine MD5-Hash-Prüfung von zwei Dateien durch (vermutlich `file1` und `file2`).
    *   Das Tool `md5collgen` wurde auf das Zielsystem transferiert.
    *   Mit `./md5collgen -p md5` (wobei `md5` eine kleine Prefix-Datei war) wurden zwei Dateien `msg1.bin` und `msg2.bin` erzeugt, die unterschiedlichen Inhalt, aber denselben MD5-Hash hatten.
    *   Die Dateien wurden in `file1` und `file2` umbenannt.
    *   Die Ausführung von `sudo /bin/bash /home/joe/coll` führte (aufgrund der MD5-Kollision) dazu, dass das Skript eine privilegierte Aktion durchführte, die eine anschließende Ausführung von `/bin/bash -p` zu einer Root-Shell eskalierte.
    *   Die Root-Flag wurde aus `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Brute-Force auf Web-Login:** Knacken von Admin-Zugangsdaten (`hydra`).
*   **Umgehung von IP-basierten Schutzmechanismen:** Durch Setzen eines benutzerdefinierten HTTP-Headers (`X-ORIGINATING-IP`).
*   **Informationslecks in Logdateien und Binaries:** Fund von Benutzernamen und Passwort-Hashes.
*   **Passwort-Cracking:** Knacken eines SHA-256 Hashes mit `hashcat`.
*   **Unsichere `sudo`-Konfiguration:** Erlaubte die Ausführung eines Skripts als `root`, das eine Schwachstelle enthielt.
*   **MD5-Kollisionsangriff:** Ausnutzung der Schwäche von MD5, um eine Integritätsprüfung in einem privilegierten Skript zu umgehen.
*   **Directory Indexing.**
*   **Fehlende Sicherheitsheader.**

## Flags

*   **User Flag (`/home/joe/user.txt`):** `cc32dbc17ec3ddf89f9e6d0991c82616`
*   **Root Flag (`/root/root.txt`):** `052cf26a6e7e33790391c0d869e2e40c`

## Tags

`HackMyVM`, `Comet`, `Medium`, `Web`, `Brute-Force`, `Hydra`, `Log Analysis`, `Hash Cracking`, `Hashcat`, `SSH`, `Sudo Privilege Escalation`, `MD5 Collision`, `Bash`, `Linux`
