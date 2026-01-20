#!/usr/bin/env python3
"""
Script de synchronisation DNS Pi-hole pour VMs Proxmox
Récupère automatiquement les VMs et leurs IPs pour créer des entrées DNS
"""

import argparse
import logging
import sys
import yaml
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from proxmox_client import ProxmoxClient, ProxmoxVMManager
from pihole_client import PiHoleClient, PiHoleDNSManager

# Désactiver les warnings SSL si verify_ssl=False
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('./pve-pihole-dns.log')
    ]
)
logger = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    """Charge le fichier de configuration YAML"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration chargée depuis {config_path}")
        return config
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la configuration: {e}")
        sys.exit(1)


def sync_vm_dns(vm_manager: ProxmoxVMManager, dns_manager: PiHoleDNSManager, 
                pool_name: str, dry_run: bool = False):
    """Synchronise les entrées DNS pour toutes les VMs et LXC"""
    vms = vm_manager.get_vms_from_pool(pool_name)
    
    if not vms:
        logger.warning("Aucune VM/LXC trouvée")
        return
    
    success_count = 0
    failed_count = 0
    
    for vm in vms:
        vmid = vm['vmid']
        name = vm['name']
        status = vm['status']
        vm_type = vm.get('vm_type', 'qemu')
        type_label = 'VM' if vm_type == 'qemu' else 'LXC'
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Traitement {type_label} {vmid} - {name} (status: {status})")
        
        # On traite uniquement les VMs/LXC en cours d'exécution
        if status != 'running':
            logger.info(f"{type_label} {vmid} non démarré(e), ignoré(e)")
            continue
        
        # Récupérer l'IP
        ip = vm_manager.get_vm_ip(vmid, vm_type)
        
        if not ip:
            logger.warning(f"{type_label} {vmid}: Impossible de récupérer l'IP, ignoré(e)")
            failed_count += 1
            continue
        
        logger.info(f"Appel add_vm_dns_entries pour VM {vmid} ({name}) avec IP {ip}")
        if dns_manager.add_vm_dns_entries(vmid, name, ip):
            logger.info(f"Entrées DNS ajoutées pour VM {vmid} ({name})")
            success_count += 1
        else:
            logger.warning(f"Échec ajout DNS pour VM {vmid} ({name})")
            failed_count += 1
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Synchronisation terminée: {success_count} succès, {failed_count} échecs")


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='Synchronisation DNS Pi-hole pour VMs Proxmox'
    )
    parser.add_argument(
        '-c', '--config',
        default='./config.yaml',
        help='Chemin du fichier de configuration (défaut: ./config.yaml)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Mode test: affiche les actions sans les exécuter'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Nettoie toutes les entrées DNS existantes avant synchronisation'
    )
    args = parser.parse_args()
    # Charger la configuration
    config = load_config(args.config)

    # Initialiser le client Proxmox
    proxmox_config = config['proxmox']
    proxmox_client = ProxmoxClient(
        host=proxmox_config['host'],
        user=proxmox_config['user'],
        token_name=proxmox_config['token_name'],
        token_value=proxmox_config['token_value'],
        node=proxmox_config['node'],
        verify_ssl=proxmox_config.get('verify_ssl', False)
    )

    proxmox2_config = config['proxmox2']
    proxmox2_client = ProxmoxClient(
        host=proxmox2_config["host"],
        user=proxmox2_config["user"],
        token_name=proxmox2_config["token_name"],
        token_value=proxmox2_config["token_value"],
        node=proxmox2_config["node"],
        verify_ssl=proxmox2_config.get("verify_ssl", False),
    )

    # Extraire le préfixe réseau (ex: "192.168.0" depuis "192.168.0.0/24")
    network_cidr = config['dns']['network_cidr']
    network_prefix = network_cidr.split('/')[0].rsplit('.', 1)[0]

    vm_manager = ProxmoxVMManager(proxmox_client, network_prefix)
    vm_manager2 = ProxmoxVMManager(proxmox2_client, network_prefix)

    # Initialiser le client Pi-hole
    pihole_config = config['pihole']
    pihole_client = PiHoleClient(
        url=pihole_config['url'],
        password=pihole_config['password']
    )

    # Authentification Pi-hole
    if not pihole_client.authenticate():
        logger.error("Impossible de s'authentifier auprès de Pi-hole")
        sys.exit(1)

    dns_manager = PiHoleDNSManager(pihole_client, config['dns']['domain'])

    # Nettoyer les anciennes entrées si demandé
    if args.clean:
        dns_manager.delete_all_pve_records(dry_run=args.dry_run)

    # Synchroniser
    pool_name = config.get('proxmox', {}).get('pool', 'homelab')
    
    
    sync_vm_dns(vm_manager, dns_manager, pool_name, dry_run=args.dry_run)

    sync_vm_dns(vm_manager2, dns_manager, pool_name, dry_run=args.dry_run)

    logger.info("\nSynchronisation terminée avec succès!")


if __name__ == '__main__':
    main()
