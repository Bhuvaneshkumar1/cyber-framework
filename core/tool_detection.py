import shutil

def tool_exists(tool):
    return shutil.which(tool) is not None