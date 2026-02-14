#!/usr/bin/env python3
"""
Validation script for agent-security-patterns repository.
Checks:
- All referenced files exist
- Threat IDs are unique and sequential
- Cross-references between THREAT-MODEL.md, DEFENSES.md, ARCHITECTURE.md
- Checklist items reference real threats
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple

class ValidationError(Exception):
    """Raised when validation fails"""
    pass

def find_repo_root() -> Path:
    """Find the repository root directory"""
    current = Path(__file__).parent.absolute()
    if (current / 'THREAT-MODEL.md').exists() and (current / 'DEFENSES.md').exists():
        return current
    raise ValidationError("Could not find repository root")

def extract_threat_ids(content: str) -> List[str]:
    """Extract all threat IDs (AT-001, AT-002, etc.) from content"""
    pattern = r'AT-(\d{3})'
    matches = re.findall(pattern, content)
    return [f'AT-{m}' for m in matches]

def extract_defense_ids(content: str) -> List[str]:
    """Extract defense pattern references from content"""
    # Look for "Defense Pattern N:" or "#defense-pattern-N"
    pattern = r'Defense Pattern (\d+)|#defense-pattern-(\d+)'
    matches = re.findall(pattern, content)
    return [f'Defense Pattern {m[0] or m[1]}' for m in matches]

def check_threat_ids_unique_sequential(repo_root: Path) -> List[str]:
    """Check that threat IDs in THREAT-MODEL.md are unique and sequential"""
    errors = []
    threat_model_path = repo_root / 'THREAT-MODEL.md'
    
    if not threat_model_path.exists():
        errors.append("THREAT-MODEL.md not found")
        return errors
    
    content = threat_model_path.read_text(encoding='utf-8')
    
    # Find all threat IDs
    threat_pattern = r'###\s+AT-(\d{3}):'
    threat_matches = re.findall(threat_pattern, content)
    
    if not threat_matches:
        errors.append("No threat IDs found in THREAT-MODEL.md")
        return errors
    
    threat_ids = [int(m) for m in threat_matches]
    
    # Check for uniqueness
    if len(threat_ids) != len(set(threat_ids)):
        duplicates = [f'AT-{tid:03d}' for tid in threat_ids if threat_ids.count(tid) > 1]
        errors.append(f"Duplicate threat IDs found: {', '.join(set(duplicates))}")
    
    # Check for sequential ordering
    sorted_ids = sorted(threat_ids)
    if threat_ids != sorted_ids:
        errors.append("Threat IDs are not in sequential order")
    
    # Check for gaps
    for i in range(len(sorted_ids) - 1):
        if sorted_ids[i + 1] - sorted_ids[i] > 1:
            errors.append(f"Gap in threat IDs: AT-{sorted_ids[i]:03d} to AT-{sorted_ids[i+1]:03d}")
    
    # Check numbering starts at 1
    if sorted_ids and sorted_ids[0] != 1:
        errors.append(f"Threat IDs should start at AT-001, but start at AT-{sorted_ids[0]:03d}")
    
    return errors

def extract_markdown_links(content: str) -> List[Tuple[str, str]]:
    """Extract all markdown links from content"""
    pattern = r'\[([^\]]+)\]\(([^)]+?)(?:\s+"[^"]*")?\)'
    return re.findall(pattern, content)

def check_file_references(repo_root: Path) -> List[str]:
    """Check that all referenced files exist"""
    errors = []
    
    # Files to check
    files_to_check = ['THREAT-MODEL.md', 'DEFENSES.md', 'ARCHITECTURE.md', 'CHECKLIST.md', 'README.md']
    
    for filename in files_to_check:
        filepath = repo_root / filename
        if not filepath.exists():
            errors.append(f"Required file not found: {filename}")
            continue
        
        content = filepath.read_text(encoding='utf-8')
        links = extract_markdown_links(content)
        
        for link_text, link_url in links:
            # Skip external links and anchors
            if link_url.startswith(('http://', 'https://', 'mailto:', '#')):
                continue
            
            # Remove anchor fragments
            link_path = link_url.split('#')[0]
            if not link_path:
                continue
            
            # Resolve relative path
            target = (filepath.parent / link_path).resolve()
            
            # Check if target exists
            if not target.exists():
                errors.append(f"{filename}: Broken link to '{link_url}'")
    
    return errors

def check_cross_references(repo_root: Path) -> List[str]:
    """Check cross-references between THREAT-MODEL.md, DEFENSES.md, ARCHITECTURE.md"""
    errors = []
    
    # Read all files
    threat_model_path = repo_root / 'THREAT-MODEL.md'
    defenses_path = repo_root / 'DEFENSES.md'
    architecture_path = repo_root / 'ARCHITECTURE.md'
    
    if not threat_model_path.exists():
        errors.append("THREAT-MODEL.md not found")
        return errors
    
    threat_content = threat_model_path.read_text(encoding='utf-8')
    
    # Extract threat IDs from THREAT-MODEL.md
    threat_pattern = r'###\s+(AT-\d{3}):'
    threat_ids = set(re.findall(threat_pattern, threat_content))
    
    # Check DEFENSES.md references valid threats
    if defenses_path.exists():
        defenses_content = defenses_path.read_text(encoding='utf-8')
        referenced_threats = set(extract_threat_ids(defenses_content))
        
        # Check if referenced threats exist
        for threat_id in referenced_threats:
            if threat_id not in threat_ids:
                errors.append(f"DEFENSES.md references non-existent threat: {threat_id}")
    
    # Check ARCHITECTURE.md references valid threats
    if architecture_path.exists():
        architecture_content = architecture_path.read_text(encoding='utf-8')
        referenced_threats = set(extract_threat_ids(architecture_content))
        
        for threat_id in referenced_threats:
            if threat_id not in threat_ids:
                errors.append(f"ARCHITECTURE.md references non-existent threat: {threat_id}")
    
    return errors

def check_checklist_references(repo_root: Path) -> List[str]:
    """Check that checklist items reference real threats or defenses"""
    errors = []
    
    checklist_path = repo_root / 'CHECKLIST.md'
    threat_model_path = repo_root / 'THREAT-MODEL.md'
    defenses_path = repo_root / 'DEFENSES.md'
    
    if not checklist_path.exists():
        errors.append("CHECKLIST.md not found")
        return errors
    
    checklist_content = checklist_path.read_text(encoding='utf-8')
    
    # Extract threat IDs from THREAT-MODEL.md
    threat_ids = set()
    if threat_model_path.exists():
        threat_content = threat_model_path.read_text(encoding='utf-8')
        threat_pattern = r'AT-\d{3}'
        threat_ids = set(re.findall(threat_pattern, threat_content))
    
    # Extract defense patterns from DEFENSES.md
    defense_patterns = set()
    if defenses_path.exists():
        defenses_content = defenses_path.read_text(encoding='utf-8')
        pattern = r'Defense Pattern \d+'
        defense_patterns = set(re.findall(pattern, defenses_content))
    
    # Check references in checklist
    checklist_threat_refs = set(extract_threat_ids(checklist_content))
    checklist_defense_refs = set(extract_defense_ids(checklist_content))
    
    # These are informational - checklist doesn't need to reference every threat
    # But if it does reference them, they should exist
    for threat_id in checklist_threat_refs:
        if threat_id not in threat_ids:
            errors.append(f"CHECKLIST.md references non-existent threat: {threat_id}")
    
    for defense_pattern in checklist_defense_refs:
        if defense_pattern not in defense_patterns:
            errors.append(f"CHECKLIST.md references non-existent defense: {defense_pattern}")
    
    return errors

def check_owasp_references(repo_root: Path) -> List[str]:
    """Check that OWASP references are consistent"""
    errors = []
    
    threat_model_path = repo_root / 'THREAT-MODEL.md'
    if not threat_model_path.exists():
        return errors
    
    content = threat_model_path.read_text(encoding='utf-8')
    
    # Look for OWASP references (ASI01, ASI02, etc.)
    owasp_pattern = r'OWASP.*?:\s*(ASI\d{2})'
    owasp_refs = re.findall(owasp_pattern, content)
    
    # Check that each threat has an OWASP reference
    threat_pattern = r'###\s+AT-\d{3}:'
    threat_count = len(re.findall(threat_pattern, content))
    
    if owasp_refs and len(owasp_refs) < threat_count:
        errors.append(f"Some threats missing OWASP references ({len(owasp_refs)}/{threat_count})")
    
    return errors

def main():
    """Run all validation checks"""
    try:
        repo_root = find_repo_root()
    except ValidationError as e:
        print(f"ERROR: {e}")
        return 1
    
    print("Validating agent-security-patterns repository...")
    print(f"Repository root: {repo_root}")
    print()
    
    all_errors = []
    
    # Check 1: Threat IDs are unique and sequential
    print("Checking threat IDs are unique and sequential...")
    errors = check_threat_ids_unique_sequential(repo_root)
    all_errors.extend(errors)
    if errors:
        for error in errors:
            print(f"  ERROR: {error}")
    else:
        print("  OK: All threat IDs are unique and sequential")
    print()
    
    # Check 2: File references
    print("Checking file references...")
    errors = check_file_references(repo_root)
    all_errors.extend(errors)
    if errors:
        for error in errors:
            print(f"  ERROR: {error}")
    else:
        print("  OK: All file references are valid")
    print()
    
    # Check 3: Cross-references between files
    print("Checking cross-references between files...")
    errors = check_cross_references(repo_root)
    all_errors.extend(errors)
    if errors:
        for error in errors:
            print(f"  ERROR: {error}")
    else:
        print("  OK: All cross-references are valid")
    print()
    
    # Check 4: Checklist references
    print("Checking checklist references...")
    errors = check_checklist_references(repo_root)
    all_errors.extend(errors)
    if errors:
        for error in errors:
            print(f"  ERROR: {error}")
    else:
        print("  OK: All checklist references are valid")
    print()
    
    # Check 5: OWASP references
    print("Checking OWASP references...")
    errors = check_owasp_references(repo_root)
    all_errors.extend(errors)
    if errors:
        for error in errors:
            print(f"  ERROR: {error}")
    else:
        print("  OK: OWASP references are consistent")
    print()
    
    # Summary
    print("=" * 60)
    if all_errors:
        print(f"FAILED: {len(all_errors)} validation error(s) found")
        return 1
    else:
        print("SUCCESS: All validation checks passed")
        return 0

if __name__ == '__main__':
    sys.exit(main())
