#!/usr/bin/env python3
"""
Tests for validate.py
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from validate import (
    find_repo_root,
    extract_threat_ids,
    extract_defense_ids,
    check_threat_ids_unique_sequential,
    extract_markdown_links,
    check_file_references,
    check_cross_references,
    check_checklist_references,
    ValidationError
)

class TestValidation(unittest.TestCase):
    """Test validation functions"""
    
    def setUp(self):
        """Create a temporary test repository"""
        self.test_dir = tempfile.mkdtemp()
        self.repo_root = Path(self.test_dir)
        
        # Create basic structure
        (self.repo_root / 'THREAT-MODEL.md').write_text('# Threat Model')
        (self.repo_root / 'DEFENSES.md').write_text('# Defenses')
        (self.repo_root / 'ARCHITECTURE.md').write_text('# Architecture')
        (self.repo_root / 'CHECKLIST.md').write_text('# Checklist')
        (self.repo_root / 'README.md').write_text('# Agent Security Patterns')
    
    def tearDown(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.test_dir)
    
    def test_extract_threat_ids(self):
        """Test threat ID extraction"""
        content = """
        ### AT-001: Direct Prompt Injection
        This threat is mitigated by AT-002 defenses.
        See also AT-015 for related threats.
        """
        threat_ids = extract_threat_ids(content)
        self.assertEqual(len(threat_ids), 3)
        self.assertIn('AT-001', threat_ids)
        self.assertIn('AT-002', threat_ids)
        self.assertIn('AT-015', threat_ids)
    
    def test_extract_defense_ids(self):
        """Test defense pattern extraction"""
        content = """
        See Defense Pattern 1 for details.
        Also refer to #defense-pattern-2.
        Defense Pattern 10 provides guidance.
        """
        defense_ids = extract_defense_ids(content)
        self.assertTrue(len(defense_ids) >= 3)
    
    def test_extract_markdown_links(self):
        """Test markdown link extraction"""
        content = """
        Here is a [link](file.md) and [another](https://example.com).
        """
        links = extract_markdown_links(content)
        self.assertEqual(len(links), 2)
        self.assertIn(('link', 'file.md'), links)
        self.assertIn(('another', 'https://example.com'), links)
    
    def test_threat_ids_sequential(self):
        """Test detection of sequential threat IDs"""
        content = """
# Threat Model

### AT-001: First Threat
Description

### AT-002: Second Threat
Description

### AT-003: Third Threat
Description
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(content)
        errors = check_threat_ids_unique_sequential(self.repo_root)
        self.assertEqual(len(errors), 0)
    
    def test_threat_ids_duplicate(self):
        """Test detection of duplicate threat IDs"""
        content = """
# Threat Model

### AT-001: First Threat
Description

### AT-001: Duplicate Threat
Description
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(content)
        errors = check_threat_ids_unique_sequential(self.repo_root)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('Duplicate' in e for e in errors))
    
    def test_threat_ids_gap(self):
        """Test detection of gaps in threat IDs"""
        content = """
# Threat Model

### AT-001: First Threat
Description

### AT-003: Third Threat (gap at AT-002)
Description
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(content)
        errors = check_threat_ids_unique_sequential(self.repo_root)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('Gap' in e for e in errors))
    
    def test_threat_ids_out_of_order(self):
        """Test detection of out-of-order threat IDs"""
        content = """
# Threat Model

### AT-002: Second Threat
Description

### AT-001: First Threat (out of order)
Description
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(content)
        errors = check_threat_ids_unique_sequential(self.repo_root)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('sequential order' in e for e in errors))
    
    def test_file_references_broken(self):
        """Test detection of broken file references"""
        content = """
# README

See [THREAT-MODEL.md](THREAT-MODEL.md) for details.
Also check [nonexistent.md](nonexistent.md).
"""
        (self.repo_root / 'README.md').write_text(content)
        errors = check_file_references(self.repo_root)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('Broken link' in e for e in errors))
    
    def test_file_references_valid(self):
        """Test when all file references are valid"""
        content = """
# README

See [THREAT-MODEL.md](THREAT-MODEL.md) for details.
"""
        (self.repo_root / 'README.md').write_text(content)
        errors = check_file_references(self.repo_root)
        self.assertEqual(len(errors), 0)
    
    def test_cross_references_invalid(self):
        """Test detection of invalid cross-references"""
        threat_content = """
# Threat Model

### AT-001: Valid Threat
Description
"""
        defenses_content = """
# Defenses

This defense addresses AT-001 and AT-999 (non-existent).
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(threat_content)
        (self.repo_root / 'DEFENSES.md').write_text(defenses_content)
        
        errors = check_cross_references(self.repo_root)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('AT-999' in e for e in errors))
    
    def test_cross_references_valid(self):
        """Test when all cross-references are valid"""
        threat_content = """
# Threat Model

### AT-001: Valid Threat
Description

### AT-002: Another Threat
Description
"""
        defenses_content = """
# Defenses

This defense addresses AT-001 and AT-002.
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(threat_content)
        (self.repo_root / 'DEFENSES.md').write_text(defenses_content)
        
        errors = check_cross_references(self.repo_root)
        self.assertEqual(len(errors), 0)
    
    def test_checklist_references_invalid(self):
        """Test detection of invalid checklist references"""
        threat_content = """
# Threat Model

### AT-001: Valid Threat
Description
"""
        checklist_content = """
# Checklist

- [ ] Mitigate AT-001
- [ ] Address AT-999 (non-existent)
"""
        (self.repo_root / 'THREAT-MODEL.md').write_text(threat_content)
        (self.repo_root / 'CHECKLIST.md').write_text(checklist_content)
        
        errors = check_checklist_references(self.repo_root)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('AT-999' in e for e in errors))

if __name__ == '__main__':
    unittest.main()
