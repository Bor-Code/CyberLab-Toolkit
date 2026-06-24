def wait_for_enter():
    input("\nPress Enter to continue...")


def read_choice(prompt="Select an option: "):
    return input(prompt).strip()


def print_invalid_choice():
    print()
    print("Invalid option. Please select a valid menu item.")