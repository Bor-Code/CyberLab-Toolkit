from colorama import Fore, Style


def read_choice(prompt="Select an option: "):
    return input(Fore.LIGHTYELLOW_EX + Style.BRIGHT + prompt + Style.RESET_ALL).strip()


def wait_for_enter():
    input(Fore.LIGHTBLACK_EX + "Press Enter to continue..." + Style.RESET_ALL)


def print_invalid_choice():
    print(Fore.LIGHTRED_EX + Style.BRIGHT + "Invalid choice. Please try again.")