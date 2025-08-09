import multiprocessing
import sys
import os

def get_cpu_count():
    """Get number of available CPUs"""
    return multiprocessing.cpu_count()

def print_banner():
    """Print tool banner"""
    banner = """
 _______       _____                _             
|___  (_)     /  __ \              | |            
   / / _ _ __ | /  \/_ __ __ _  ___| | _____ _ __ 
  / / | | '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
./ /__| | |_) | \__/\ | | (_| | (__|   <  __/ |   
\_____/_| .__/ \____/_|  \__,_|\___|_|\_\___|_|   
        | |                                       
        |_| 
                                                              
#Original creator Asaotomo@Hx0-Team               Update:2025.08.09
    """
    print(banner)