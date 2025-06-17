import os
import platform

def to_network_path(local_path): #normalize local path to network path
    if not local_path:
        return '/'
    
    # clean up path 
    normalized = os.path.normpath(local_path)
    # Replace backslashes with forward slashes
    network_path = normalized.replace('\\', '/')
    
    # Remove drive letter for Windows paths (e.g., C:/path -> /path)
    if platform.system() == 'Windows' and ':' in network_path:
        network_path = network_path[2:] if network_path[1] == ':' else network_path
    
    # Ensure the path starts with a single forward slash
    network_path = '/' + network_path.lstrip('/')
    
    return network_path

def from_network_path(network_path):
    if not network_path or network_path == '/':
        return get_root()
    
    # Remove leading slash for processing
    clean_path = network_path.lstrip('/')
    
    if platform.system() == 'Windows':
        # Convert to Windows format with backslashes
        local_path = clean_path.replace('/', '\\')
        # get root directory for Windows
        return os.path.join(get_root(), local_path)
    else:
        # For Unix, ensure the path starts with /
        return '/' + clean_path

def get_root():
    if platform.system() == 'Windows':
        return os.environ.get('SYSTEMDRIVE', 'C:') + '\\'
    else:
        return '/'

def safe_path_join(base_path, *paths): #*paths allows for many path compnenents to be joined (tuple)
    return os.path.normpath(os.path.join(base_path, *paths))