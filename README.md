# Installer les dépendances Python

```bash
pip3 install -r requirements.txt
```

Ou avec un environnement virtuel (recommandé) :

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Installer le service systemd

```bash
sudo cp systemd/pve-pihole-dns.service /etc/systemd/system/
sudo cp systemd/pve-pihole-dns.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pve-pihole-dns. timer
sudo systemctl start pve-pihole-dns.timer
```