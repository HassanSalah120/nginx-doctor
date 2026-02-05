"""Tests for the nginx configuration parser."""

import pytest

from nginx_doctor.parser.nginx_conf import NginxConfigParser


class TestNginxConfigParser:
    """Test nginx -T output parsing."""

    def test_parse_extracts_version(self, sample_nginx_t_output):
        """Parser should preserve version passed to it."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output, version="1.24.0")
        
        assert info.version == "1.24.0"

    def test_parse_extracts_config_path(self, sample_nginx_t_output):
        """Parser should extract main config path."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        assert "nginx.conf" in info.config_path

    def test_parse_finds_server_blocks(self, sample_nginx_t_output):
        """Parser should find all server blocks."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        assert len(info.servers) >= 2

    def test_parse_tracks_source_files(self, sample_nginx_t_output):
        """Parser should track which file each block came from."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        # At least one server should have source file tracked
        servers_with_source = [s for s in info.servers if s.source_file]
        assert len(servers_with_source) > 0

    def test_parse_extracts_server_names(self, sample_nginx_t_output):
        """Parser should extract server_name directives."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        all_names = []
        for server in info.servers:
            all_names.extend(server.server_names)
        
        assert "_" in all_names or "laravel.example.com" in all_names

    def test_parse_extracts_locations(self, sample_nginx_t_output):
        """Parser should extract location blocks."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        # Find server with locations
        servers_with_locations = [s for s in info.servers if s.locations]
        assert len(servers_with_locations) > 0

    def test_parse_tracks_line_numbers(self, sample_nginx_t_output):
        """Parser should track line numbers for evidence."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        # Server blocks should have line numbers
        for server in info.servers:
            assert server.line_number > 0

    def test_parse_collects_includes(self, sample_nginx_t_output):
        """Parser should track all included files."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        assert len(info.includes) > 0
