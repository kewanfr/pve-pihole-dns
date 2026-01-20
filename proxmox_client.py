#!/usr/bin/env python3
"""
Client API Proxmox
Gestion des VMs et conteneurs LXC
"""

import logging
from typing import List, Dict, Optional
from proxmoxer import ProxmoxAPI

logger = logging.getLogger(__name__)


class ProxmoxClient:
    """Client pour l'API Proxmox"""
    
    def __init__(self, host: str, user: str, token_name: str, token_value: str, 
                 node: str, verify_ssl: bool = False):
        self.host = host
        self.node = node
        self.proxmox = self._connect(host, user, token_name, token_value, verify_ssl)
    
    def _connect(self, host: str, user: str, token_name: str, 
                 token_value: str, verify_ssl: bool) -> ProxmoxAPI:
        """Connexion à l'API Proxmox"""
        try:
            proxmox = ProxmoxAPI(
                host,
                user=user,
                token_name=token_name,
                token_value=token_value,
                verify_ssl=verify_ssl
            )
            logger.info(f"Connecté à Proxmox: {host}")
            return proxmox
        except Exception as e:
            logger.error(f"Erreur de connexion à Proxmox: {e}")
            raise
    
    def get_pool_members(self, pool_name: str) -> List[Dict]:
        """Récupère les membres d'un resource pool"""
        try:
            pool_data = self.proxmox.pools(pool_name).get()
            return pool_data.get('members', [])
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du pool '{pool_name}': {e}")
            return []
    
    def get_qemu_vms(self) -> List[Dict]:
        """Récupère toutes les VMs QEMU du node"""
        try:
            return self.proxmox.nodes(self.node).qemu.get()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des VMs: {e}")
            return []
    
    def get_lxc_containers(self) -> List[Dict]:
        """Récupère tous les conteneurs LXC du node"""
        try:
            return self.proxmox.nodes(self.node).lxc.get()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des LXC: {e}")
            return []
    
    def get_qemu_network_info(self, vmid: int) -> Optional[Dict]:
        """Récupère les infos réseau d'une VM via l'agent QEMU"""
        try:
            return self.proxmox.nodes(self.node).qemu(vmid).agent('network-get-interfaces').get()
        except Exception as e:
            logger.warning(f"VM {vmid}: Erreur agent QEMU: {e}")
            return None
    
    def get_lxc_network_info(self, vmid: int) -> Optional[List]:
        """Récupère les infos réseau d'un conteneur LXC"""
        try:
            return self.proxmox.nodes(self.node).lxc(vmid).interfaces.get()
        except Exception as e:
            logger.warning(f"LXC {vmid}: Erreur récupération interfaces: {e}")
            return None


class ProxmoxVMManager:
    """Gestionnaire haut niveau pour les VMs/LXC Proxmox"""
    
    def __init__(self, client: ProxmoxClient, network_prefix: str):
        self.client = client
        self.network_prefix = network_prefix
    
    def get_vms_from_pool(self, pool_name: str = "homelab") -> List[Dict]:
        """Récupère les VMs et LXC d'un resource pool"""
        pool_members = self.client.get_pool_members(pool_name)
        
        # Séparer les VMs QEMU et les LXC du bon node
        qemu_ids = [
            m['vmid'] for m in pool_members 
            if m.get('type') == 'qemu' and m.get('node') == self.client.node
        ]
        lxc_ids = [
            m['vmid'] for m in pool_members 
            if m.get('type') == 'lxc' and m.get('node') == self.client.node
        ]
        
        # Récupérer les infos complètes
        all_qemu = self.client.get_qemu_vms()
        vms = [dict(vm, vm_type='qemu') for vm in all_qemu if vm['vmid'] in qemu_ids]
        
        all_lxc = self.client.get_lxc_containers()
        lxc_list = [dict(ct, vm_type='lxc') for ct in all_lxc if ct['vmid'] in lxc_ids]
        
        vms.extend(lxc_list)
        
        logger.info(f"Trouvé {len(qemu_ids)} VMs et {len(lxc_ids)} LXC dans le pool '{pool_name}'")
        return vms
    
    def get_vm_ip(self, vmid: int, vm_type: str = 'qemu') -> Optional[str]:
        """Récupère l'IP d'une VM ou LXC"""
        if vm_type == 'qemu':
            return self._get_qemu_ip(vmid)
        else:
            return self._get_lxc_ip(vmid)
    
    def _get_qemu_ip(self, vmid: int) -> Optional[str]:
        """Récupère l'IP d'une VM QEMU via l'agent"""
        network_info = self.client.get_qemu_network_info(vmid)
        
        if not network_info or 'result' not in network_info:
            logger.warning(f"VM {vmid}: Agent QEMU non disponible")
            return None
        
        for interface in network_info['result']:
            if interface.get('name') in ['lo', 'docker0']:
                continue
            
            for ip_info in interface.get('ip-addresses', []):
                ip = ip_info.get('ip-address', '')
                ip_type = ip_info.get('ip-address-type', '')
                
                if ip_type == 'ipv4' and ip.startswith(self.network_prefix):
                    logger.info(f"VM {vmid}: IP trouvée {ip}")
                    return ip
        
        logger.warning(f"VM {vmid}: Aucune IP trouvée dans le réseau {self.network_prefix}.x")
        return None
    
    def _get_lxc_ip(self, vmid: int) -> Optional[str]:
        """Récupère l'IP d'un conteneur LXC"""
        interfaces = self.client.get_lxc_network_info(vmid)
        
        if not interfaces:
            logger.warning(f"LXC {vmid}: Pas d'infos réseau")
            return None
        
        for interface in interfaces:
            if interface.get('name') in ['lo', 'docker0']:
                continue
            
            ip = interface.get('inet', '').split('/')[0]
            if ip and ip.startswith(self.network_prefix):
                logger.info(f"LXC {vmid}: IP trouvée {ip}")
                return ip
        
        logger.warning(f"LXC {vmid}: Aucune IP trouvée dans le réseau {self.network_prefix}.x")
        return None
