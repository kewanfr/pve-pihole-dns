#!/usr/bin/env python3
"""
Client API Pi-hole v6
Gestion de l'authentification et des entrées DNS
"""

import logging
import requests
import time
from typing import List, Optional

logger = logging.getLogger(__name__)


class PiHoleClient:
    """Client pour l'API Pi-hole v6"""
    
    def __init__(self, url: str, password: str):
        self.url = url.rstrip('/')
        self.password = password
        self.session = requests.Session()
        self.csrf_token: Optional[str] = None
        self.sid: Optional[str] = None
        self._dns_hosts_cache: Optional[List[str]] = None
        self._cname_records_cache: Optional[List[str]] = None
    
    def authenticate(self) -> bool:
        """Authentification auprès de Pi-hole"""
        try:
            response = self.session.post(
                f"{self.url}/api/auth",
                json={"password": self.password},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            session_info = data.get('session', {})
            if session_info.get('valid'):
                self.sid = session_info.get('sid')
                self.csrf_token = session_info.get('csrf')
                
                # Configurer le cookie sid et le header CSRF pour les futures requêtes
                self.session.cookies.set('sid', self.sid)
                self.session.headers.update({'X-CSRF-TOKEN': self.csrf_token})
                
                logger.info(f"Authentification Pi-hole réussie (validité: {session_info.get('validity')}s)")
                return True
            else:
                logger.error(f"Authentification Pi-hole échouée: {session_info.get('message')}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur d'authentification Pi-hole: {e}")
            return False
    
    def _request(self, method: str, endpoint: str, delay: bool = True, **kwargs) -> Optional[dict]:
        """Effectue une requête authentifiée"""
        try:
            headers = {
                'Cookie': f'sid={self.sid}',
                'X-CSRF-TOKEN': self.csrf_token
            }
            
            response = requests.request(
                method,
                f"{self.url}{endpoint}",
                headers=headers,
                timeout=10,
                **kwargs
            )
            response.raise_for_status()
            
            # Délai de 1s seulement pour les requêtes de modification (PUT/DELETE)
            if delay and method in ['PUT', 'DELETE']:
                time.sleep(1.0)
            
            return response.json()
        except Exception as e:
            logger.error(f"Erreur API Pi-hole ({method} {endpoint}): {e}")
            return None
    
    # ==================== DNS Hosts ====================
    
    def get_dns_hosts(self, use_cache: bool = True) -> List[str]:
        """Récupère la liste des entrées DNS hosts"""
        if use_cache and self._dns_hosts_cache is not None:
            return self._dns_hosts_cache
        
        data = self._request('GET', '/api/config/dns/hosts', delay=False)
        if data:
            self._dns_hosts_cache = data.get('config', {}).get('dns', {}).get('hosts', [])
            return self._dns_hosts_cache
        return []
    
    def dns_host_exists(self, ip: str, domain: str) -> bool:
        """Vérifie si une entrée DNS existe déjà"""
        entry = f"{ip} {domain}"
        return entry in self.get_dns_hosts()
    
    def add_dns_host(self, ip: str, domain: str) -> bool:
        """Ajoute une entrée DNS host (ignore si existe déjà)"""
        entry = f"{ip} {domain}"
        
        # Vérifier si l'entrée existe déjà
        if self.dns_host_exists(ip, domain):
            logger.info(f"⏭ DNS existe déjà: {entry}")
            return True
        
        encoded_entry = requests.utils.quote(entry, safe='')
        
        data = self._request('PUT', f'/api/config/dns/hosts/{encoded_entry}')
        if data:
            # Mettre à jour le cache
            if self._dns_hosts_cache is not None:
                self._dns_hosts_cache.append(entry)
            logger.info(f"✓ DNS ajouté: {entry}")
            return True
        logger.error(f"✗ Échec ajout DNS: {entry}")
        return False
    
    def delete_dns_host(self, ip: str, domain: str) -> bool:
        """Supprime une entrée DNS host"""
        entry = f"{ip} {domain}"
        encoded_entry = requests.utils.quote(entry, safe='')
        
        data = self._request('DELETE', f'/api/config/dns/hosts/{encoded_entry}')
        if data:
            # Mettre à jour le cache
            if self._dns_hosts_cache is not None and entry in self._dns_hosts_cache:
                self._dns_hosts_cache.remove(entry)
            logger.info(f"✓ DNS supprimé: {entry}")
            return True
        logger.error(f"✗ Échec suppression DNS: {entry}")
        return False
    
    # ==================== CNAME Records ====================
    
    def get_cname_records(self, use_cache: bool = True) -> List[str]:
        """Récupère la liste des entrées CNAME"""
        if use_cache and self._cname_records_cache is not None:
            return self._cname_records_cache
        
        data = self._request('GET', '/api/config/dns/cnameRecords', delay=False)
        if data:
            self._cname_records_cache = data.get('config', {}).get('dns', {}).get('cnameRecords', [])
            return self._cname_records_cache
        return []
    
    def cname_record_exists(self, alias: str, target: str) -> bool:
        """Vérifie si une entrée CNAME existe déjà"""
        entry = f"{alias},{target}"
        return entry in self.get_cname_records()
    
    def add_cname_record(self, alias: str, target: str) -> bool:
        """Ajoute une entrée CNAME (ignore si existe déjà)"""
        entry = f"{alias},{target}"
        
        # Vérifier si l'entrée existe déjà
        if self.cname_record_exists(alias, target):
            logger.info(f"⏭ CNAME existe déjà: {alias} -> {target}")
            return True
        
        encoded_entry = requests.utils.quote(entry, safe='')
        
        data = self._request('PUT', f'/api/config/dns/cnameRecords/{encoded_entry}')
        if data:
            # Mettre à jour le cache
            if self._cname_records_cache is not None:
                self._cname_records_cache.append(entry)
            logger.info(f"✓ CNAME ajouté: {alias} -> {target}")
            return True
        logger.error(f"✗ Échec ajout CNAME: {alias} -> {target}")
        return False
    
    def delete_cname_record(self, alias: str, target: str) -> bool:
        """Supprime une entrée CNAME"""
        entry = f"{alias},{target}"
        encoded_entry = requests.utils.quote(entry, safe='')
        
        data = self._request('DELETE', f'/api/config/dns/cnameRecords/{encoded_entry}')
        if data:
            # Mettre à jour le cache
            if self._cname_records_cache is not None and entry in self._cname_records_cache:
                self._cname_records_cache.remove(entry)
            logger.info(f"✓ CNAME supprimé: {alias} -> {target}")
            return True
        logger.error(f"✗ Échec suppression CNAME: {alias} -> {target}")
        return False


class PiHoleDNSManager:
    """Gestionnaire haut niveau pour les entrées DNS Pi-hole"""

    def __init__(self, client: PiHoleClient, domain: str):
        self.client = client
        self.domain = domain

    def add_dns_record(self, domain: str, ip: str, dry_run: bool = False) -> bool:
        """Ajoute une entrée DNS A"""
        full_domain = f"{domain}"

        if dry_run:
            logger.info(f"[DRY-RUN] Ajouterait DNS: {full_domain} -> {ip}")
            return True

        return self.client.add_dns_host(ip, full_domain)

    def delete_dns_record(
        self, domain: str, ip: str, dry_run: bool = False
    ) -> bool:
        """Supprime une entrée DNS A"""
        full_domain = f"{domain}"

        if dry_run:
            logger.info(f"[DRY-RUN] Supprimerait DNS: {full_domain} -> {ip}")
            return True

        return self.client.delete_dns_host(ip, full_domain)

    def add_cname_record(self, alias: str, target: str, dry_run: bool = False) -> bool:
        """Ajoute une entrée CNAME"""
        full_alias = f"{alias}.{self.domain}"
        full_target = f"{target}.{self.domain}"

        if dry_run:
            logger.info(f"[DRY-RUN] Ajouterait CNAME: {full_alias} -> {full_target}")
            return True

        return self.client.add_cname_record(full_alias, full_target)

    def delete_cname_record(self, alias: str, target: str, dry_run: bool = False) -> bool:
        """Supprime une entrée CNAME"""
        full_alias = f"{alias}.{self.domain}"
        full_target = f"{target}.{self.domain}"

        if dry_run:
            logger.info(f"[DRY-RUN] Supprimerait CNAME: {full_alias} -> {full_target}")
            return True

        return self.client.delete_cname_record(full_alias, full_target)

    def delete_all_pve_records(self, dry_run: bool = False) -> None:
        """Supprime toutes les entrées DNS existantes pour *.{domain}"""
        logger.info(f"Nettoyage des anciennes entrées *.{self.domain}...")

        # Supprimer les DNS hosts
        for record in self.client.get_dns_hosts():
            if self.domain in record:
                parts = record.split(' ', 1)
                if len(parts) == 2:
                    ip, domain = parts
                    if dry_run:
                        logger.info(f"[DRY-RUN] Supprimerait: {record}")
                    else:
                        self.client.delete_dns_host(ip, domain)

        # Supprimer les CNAME
        for record in self.client.get_cname_records():
            if self.domain in record:
                parts = record.split(',', 1)
                if len(parts) == 2:
                    alias, target = parts
                    if dry_run:
                        logger.info(f"[DRY-RUN] Supprimerait CNAME: {record}")
                    else:
                        self.client.delete_cname_record(alias, target)

    def add_vm_dns_entries(self, vm_id: int, vm_name: str, ip_reelle: str) -> bool:
        """Ajoute les entrées DNS pour une VM donnée avec l'IP réelle et 10.0.0.X, plus l'alias."""
        success = True

        domain = f"{vm_id}.pve.hosts"
        # 1. Enregistrement A avec l'IP réelle
        logger.info(f"Ajout DNS: {domain} -> {ip_reelle}")
        if not self.add_dns_record(domain, ip_reelle, False):
            logger.error(f"Échec de l'ajout de l'entrée DNS pour {domain} -> {ip_reelle}")
            success = False

        # 2. Enregistrement A avec 10.0.0.X
        ip_alt = f"10.0.0.{vm_id}"
        logger.info(f"Ajout DNS: {domain} -> {ip_alt}")
        if not self.add_dns_record(domain, ip_alt, False):
            logger.error(f"Échec de l'ajout de l'entrée DNS pour {domain} -> {ip_alt}")
            success = False

        # 3. Premier alias: name.pve.hosts -> vmid.pve.hosts
        alias1 = f"{vm_name}.pve.hosts"
        target1 = f"{vm_id}.pve.hosts"
        logger.info(f"Ajout alias: {alias1} -> {target1}")
        if not self.client.add_cname_record(alias1, target1):
            logger.error(f"Échec de l'ajout de la redirection CNAME pour {alias1} -> {target1}")
            success = False

        # 4. Deuxième alias: name.hosts -> name.pve.hosts
        alias2 = f"{vm_name}.hosts"
        target2 = f"{vm_name}.pve.hosts"
        logger.info(f"Ajout alias: {alias2} -> {target2}")
        if not self.client.add_cname_record(alias2, target2):
            logger.error(f"Échec de l'ajout de la redirection CNAME pour {alias2} -> {target2}")
            success = False

        # 4. Troisième alias: name.internal -> name.pve.hosts
        alias2 = f"{vm_name}.internal"
        target2 = f"{vm_name}.pve.internal"
        logger.info(f"Ajout alias: {alias2} -> {target2}")
        if not self.client.add_cname_record(alias2, target2):
            logger.error(
                f"Échec de l'ajout de la redirection CNAME pour {alias2} -> {target2}"
            )
            success = False

        return success
