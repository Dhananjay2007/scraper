# main.py

import os
import importlib
import sys
import logging

# Configure logging
logging.basicConfig(
    filename='reports/execution.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def list_modules():
    """List all available modules from 'apis' and 'scrapers' directories."""
    modules = {}
    module_number = 1

    # List APIs
    api_dir = "apis"
    if os.path.isdir(api_dir):
        for filename in os.listdir(api_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                modules[module_number] = {
                    "name": f"{module_name} API",
                    "module": module_name,
                    "type": "apis"
                }
                module_number += 1

    # List Scrapers
    scraper_dir = "scrapers"
    if os.path.isdir(scraper_dir):
        for filename in os.listdir(scraper_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                modules[module_number] = {
                    "name": f"{module_name.capitalize()} Scraper",
                    "module": module_name,
                    "type": "scrapers"
                }
                module_number += 1

    return modules

def execute_module(module_info):
    """Dynamically import and execute the selected module's main() function."""
    module_type = module_info["type"]
    module_name = module_info["module"]

    try:
        if module_type == "apis":
            # Import from 'apis' package
            module = importlib.import_module(f"apis.{module_name}")
        elif module_type == "scrapers":
            # Import from 'scrapers' package
            module = importlib.import_module(f"scrapers.{module_name}")
        else:
            print(f"Unknown module type: {module_type}")
            logging.error(f"Unknown module type: {module_type}")
            return

        if hasattr(module, "main"):
            print(f"\nExecuting {module_info['name']}...\n")
            logging.info(f"Executing {module_info['name']}")
            module.main()
            print(f"\n{module_info['name']} execution completed.\n")
            logging.info(f"{module_info['name']} execution completed.")
        else:
            print(f"The module '{module_name}' does not have a 'main()' function.")
            logging.warning(f"The module '{module_name}' does not have a 'main()' function.")

    except ModuleNotFoundError:
        print(f"Module '{module_name}' not found in '{module_type}' directory.")
        logging.error(f"Module '{module_name}' not found in '{module_type}' directory.")
    except Exception as e:
        print(f"An error occurred while executing '{module_info['name']}': {e}")
        logging.error(f"Error executing '{module_info['name']}': {e}")

def main():
    # Add project directories to sys.path to allow imports
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, current_dir)

    modules = list_modules()
    if not modules:
        print("No API or scraper modules found.")
        logging.warning("No API or scraper modules found.")
        return

    print("Available Modules:")
    for num, info in modules.items():
        print(f"{num}. {info['name']}")

    try:
        choice = int(input("Select a module to execute (enter number): ").strip())
        if choice in modules:
            selected_module_info = modules[choice]
            execute_module(selected_module_info)
        else:
            print("Invalid choice. Please select a valid number.")
            logging.warning(f"Invalid choice entered: {choice}")
    except ValueError:
        print("Invalid input. Please enter a number.")
        logging.warning("Non-integer input received.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
