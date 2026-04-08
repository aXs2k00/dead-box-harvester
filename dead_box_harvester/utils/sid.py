"""Utility functions for extracting user SID from registry"""

import logging
import struct
from pathlib import Path
from typing import Optional, List, Dict


logger = logging.getLogger(__name__)


def extract_user_sids(backup_path: Path) -> List[Dict[str, str]]:
    """Extract user SIDs from SAM hive"""
    sids = []
    
    sam_path = backup_path / "Windows" / "System32" / "config" / "SAM"
    if not sam_path.exists():
        logger.warning(f"SAM hive not found: {sam_path}")
        return sids
    
    try:
        with open(sam_path, 'rb') as f:
            data = f.read()
        
        # Look for SID patterns in the hive
        # SIDs follow pattern: S-1-5-21-XXX-XXX-XXX-XXX
        import re
        
        # Find all potential SID strings
        sid_pattern = rb'S-1-5-21-\d{8,10}-\d{8,10}-\d{8,10}-\d{3,6}'
        for match in re.finditer(sid_pattern, data):
            sid_bytes = match.group()
            try:
                sid = sid_bytes.decode('ascii')
                if sid not in [s['sid'] for s in sids]:
                    sids.append({
                        'sid': sid,
                        'source': 'SAM',
                        'type': 'local'
                    })
            except:
                pass
        
        logger.info(f"Found {len(sids)} user SIDs")
        
    except Exception as e:
        logger.error(f"Error extracting SIDs: {e}")
    
    return sids


def extract_username_sid_map(backup_path: Path) -> Dict[str, str]:
    """Extract username to SID mapping from SAM"""
    mapping = {}
    
    sam_path = backup_path / "Windows" / "System32" / "config" / "SAM"
    if not sam_path.exists():
        return mapping
    
    try:
        with open(sam_path, 'rb') as f:
            data = f.read()
        
        # Look for username strings followed by RID
        # In SAM, usernames are stored alongside their RID
        import re
        
        # Find usernames (ASCII strings between 1-20 chars)
        username_pattern = rb'[\x20-\x7e]{1,20}'
        for match in re.finditer(username_pattern, data):
            username = match.group().decode('ascii')
            # Skip common strings
            if username.lower() in ['default', 'guest', 'administrator', 'admin']:
                # Try to find nearby SID
                pos = match.start()
                nearby = data[pos:pos+100]
                sid_match = re.search(rb'S-1-5-21-\d+-\d+-\d+-\d+', nearby)
                if sid_match:
                    sid = sid_match.group().decode('ascii')
                    mapping[username.lower()] = sid
        
    except Exception as e:
        logger.debug(f"Error building username-SID map: {e}")
    
    return mapping


def find_user_profile_for_sid(backup_path: Path, sid: str) -> Optional[Path]:
    """Find user profile directory matching SID"""
    users_path = backup_path / "Users"
    if not users_path.exists():
        return None
    
    # Check for directory named after SID
    for item in users_path.iterdir():
        if item.is_dir() and item.name == sid:
            return item
    
    # Try to match last part of SID to username
    rid = sid.split('-')[-1]
    # Common RID to username mapping
    rid_map = {
        '500': 'Administrator',
        '501': 'Guest',
        '1000': 'User',
    }
    
    username = rid_map.get(rid, f'User_{rid}')
    user_path = users_path / username
    if user_path.exists():
        return user_path
    
    return None