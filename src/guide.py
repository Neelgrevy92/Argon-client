from colorama import Fore, Back, Style
from colorama import init
init(autoreset=True)
import os 


def guide():
    try:
        os.system(r'cls')
        header = r"""________________________________________________________________________________________________________________________

    GENERAL INFORMATIONS 
________________________________________________________________________________________________________________________
        """
        print(Fore.CYAN + header)

        # Intro
        print(Fore.CYAN + '- What is I2P ?')
        print('==> I2P (Invisible Internet Project) is an anonymous overlay network that allows secure communication and hidden services. It uses garlic routing (like Tor) for privacy.')

        print(Fore.CYAN + '- What is this client purpose ?')
        print('==> This client allows you to interact with the I2P network in order to safely exchange anonymous messages using PGP.')

        print(Fore.CYAN + '- Why should I use this type of service ?')
        print('==> Privacy is a human right. I2P lets you communicate and browse anonymously, reducing tracking, surveillance, and exposure of your data.')

        print(Fore.CYAN + '- Is I2P secure ?')
        print('==> I2P provides strong anonymization with garlic routing. However, by default, traffic is not end-to-end encrypted outside of I2P tunnels, so entry/exit nodes could theoretically see unencrypted traffic.')

        print(Fore.CYAN + '- How to encrypt communications ?')
        print('==> We use by default PGP encryption on top of I2P tunnels. This ensures messages remain confidential even if an exit node is compromised.')
        

        print(Fore.CYAN + '- Are my keys safe in this client ?')
        print('==> Private keys are never stored in cleartext. They are encrypted with Argon2 before saving. The password is not stored, so keep it safe. Accessing keys directly from RAM is possible if the client is open, so use caution.')


        print(Fore.CYAN + '- Can this client be used for illegal activities ?')
        print('==> Absolutely not. This client is for privacy, security, and research purposes only. Misuse is strictly prohibited.')


        print('-----------------------------[I2P SPECIFIC]------------------------------------')
        print(Fore.CYAN + '- What is a tunnel creation success rate ?')
        print('==> It indicates how often your tunnels are successfully built. A low rate can impact connectivity and joining hidden services.')

        print(Fore.CYAN + '- What does "Firewalled" mean in network status ?')
        print('==> It means your I2P node cannot accept incoming connections directly. You can still communicate and join tunnels, but performance may be reduced.')

        print(Fore.CYAN + '- What is the difference between client and transit tunnels ?')
        print('==> Client tunnels carry your traffic through the network. Transit tunnels help relay other users’ traffic, contributing to the network\'s health and performance.')

        print(Fore.CYAN + '- What are services like SAM, I2CP, or BOB ?')
        print('==> SAM: API for applications to interact with I2P. I2CP: Protocol for routers and clients. BOB: Simple chat protocol. Enabled services indicate available features in your client.')

       
        print(Fore.CYAN + '- How to monitor my network health ?')
        print('==> Use the I2P health check in this client to monitor uptime, tunnel success, received/sent data, and transit tunnels. Alerts indicate potential issues.')

        input(Fore.YELLOW + "\nPress ENTER to return to the main menu..." + Style.RESET_ALL)
        return 

    except KeyboardInterrupt:
        print("\n" + Fore.GREEN + "[INFO] CTRL+C detected, returning to main menu..." + Style.RESET_ALL)
        return
