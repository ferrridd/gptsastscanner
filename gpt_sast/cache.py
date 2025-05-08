import os
import json
import sqlite3
import hashlib
import time
import logging

class ScanCache:
    """Handles caching of scan results to improve performance."""
    
    def __init__(self, db_path):
        """Initialize the cache with a SQLite database."""
        self.db_path = db_path
        self.logger = logging.getLogger('gpt_sast.cache')
        
        if db_path:
            os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
            self._setup_db()
    
    def _setup_db(self):
        """Set up SQLite database for caching scan results."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scans (
            file_hash TEXT PRIMARY KEY,
            file_path TEXT,
            last_modified REAL,
            last_scanned REAL,
            vulnerabilities TEXT,
            model TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS project_scans (
            project_path TEXT PRIMARY KEY,
            structure_hash TEXT,
            critical_files TEXT,
            last_scanned REAL,
            model TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT,
            last_updated REAL
        )
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Cache database set up at {self.db_path}")
    
    def _get_file_hash(self, file_path, content):
        """Generate a hash for a file based on its content."""
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
        return hashlib.md5((file_path + content_hash).encode()).hexdigest()
    
    def _get_structure_hash(self, structure):
        """Generate a hash for a project structure."""
        return hashlib.md5(json.dumps(structure, sort_keys=True).encode()).hexdigest()
    
    def get_file_vulnerabilities(self, file_path, content):
        """Check if a scan for this file is cached and still valid."""
        if not self.db_path:
            return None
            
        file_hash = self._get_file_hash(file_path, content)
        last_modified = os.path.getmtime(file_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT vulnerabilities FROM file_scans WHERE file_hash = ? AND last_modified = ?",
            (file_hash, last_modified)
        )
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None
        
        return None
    
    def save_file_vulnerabilities(self, file_path, content, vulnerabilities):
        """Save scan results to cache."""
        if not self.db_path:
            return
            
        file_hash = self._get_file_hash(file_path, content)
        last_modified = os.path.getmtime(file_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR REPLACE INTO file_scans VALUES (?, ?, ?, ?, ?, ?)",
            (file_hash, file_path, last_modified, time.time(), json.dumps(vulnerabilities), "current")
        )
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Cached vulnerabilities for {file_path}")
    
    def get_project_critical_files(self, project_path, structure):
        """Check if a project structure scan is cached and still valid."""
        if not self.db_path:
            return None
            
        structure_hash = self._get_structure_hash(structure)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT critical_files FROM project_scans WHERE project_path = ? AND structure_hash = ?",
            (project_path, structure_hash)
        )
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None
        
        return None
    
    def save_project_critical_files(self, project_path, structure, critical_files):
        """Save project scan results to cache."""
        if not self.db_path:
            return
            
        structure_hash = self._get_structure_hash(structure)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR REPLACE INTO project_scans VALUES (?, ?, ?, ?, ?)",
            (project_path, structure_hash, json.dumps(critical_files), time.time(), "current")
        )
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Cached critical files for project {project_path}")
    
    def save_metadata(self, key, value):
        """Save metadata to cache."""
        if not self.db_path:
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?, ?)",
            (key, json.dumps(value), time.time())
        )
        
        conn.commit()
        conn.close()
    
    def get_metadata(self, key):
        """Get metadata from cache."""
        if not self.db_path:
            return None
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT value FROM metadata WHERE key = ?",
            (key,)
        )
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None
        
        return None
    
    def clear_cache(self):
        """Clear all cache data."""
        if not self.db_path or not os.path.exists(self.db_path):
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM file_scans")
        cursor.execute("DELETE FROM project_scans")
        cursor.execute("DELETE FROM metadata")
        
        conn.commit()
        conn.close()
        
        self.logger.info("Cache cleared")
    
    def get_cache_stats(self):
        """Get statistics about cache usage."""
        if not self.db_path or not os.path.exists(self.db_path):
            return {"file_scans": 0, "project_scans": 0, "metadata": 0}
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM file_scans")
        file_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM project_scans")
        project_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM metadata")
        metadata = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "file_scans": file_scans,
            "project_scans": project_scans,
            "metadata": metadata
        }