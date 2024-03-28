#include "logo.h"

void send_logo(void)
{
    uart_send_string(

        "   .~~.   .~~.\n"
        "  '. \\ ' ' / .'\n"
        "   .~ .~~~..~.\n"
        "  : .~.'~'.~. :\n"
        " ~ (   ) (   ) ~\n"
        "( : '~'.~.'~' : )\n"
        " ~ .~ (   ) ~. ~\n"
        "  (  : '~' :  )\n"
        "   '~ .~~~. ~'\n"
        "       '~'\n");
}

void send_asiagodtone(void)
{
    uart_send_string(
        "                             =##*####*=.                        \n"
        "                          =%%##%%@@%%##%%#:                     \n"
        "                      :*%%%%%%%##%%%@%##%%%-                    \n"
        "                      *%@@@@@%%%#+=+#%%%%%%#                    \n"
        "                    :%%@@@%##*+: ...:=#%@%%#                    \n"
        "                     #@@%#*+++*+=-=+*++*#%%%                    \n"
        "                     :%%+=+*+*+=: :=*#*+=+%%                    \n"
        "                      -*=-:   ::   .      *                     \n"
        "                       ===--::+****:::.....                     \n"
        "       -=::           -=====--++=--=-::::                       \n"
        "       -:          .=#%#++++=-:***+==-:-                        \n"
        "       -==:   ::.*#%%%%%@%###=  .:==+***:                       \n"
        "      .-=-. -+-: #####%%%%%@@#+: .###%%##%%##*                  \n"
        "      .===:       %####%%%@@@@*=  .+*%##%%#%####=               \n"
        "      ---====      %#####%#%%@#-:.  =##%%%%%#%###*              \n"
        "      =-====-      .%%%#%%%%%%%*+:.   :+#%%##%%%###-            \n"
        "    +##+===-:      =%%%%%%%%%%%%+=:.       +#%#######.          \n"
        "   #%#%%=----.    =%%%%%%%%%@@%%%#*+=-:.       :+#%%###=        \n"
        "   #%%%#+=----:. -%%@%%%%@@@@@@%%%%%%#*=-::.          :=*       \n"
        "  %%##=-----====*%%@%%%%%@@@@@@@@@@%%%%%*+==-::...      .:      \n"
        " **---=------=++%%@@%%%%%%%@@@@@@@@@@@@@@@%*++==----::::...     \n"
        ".*=====-----===+%%@@%%%%@@@@@@@@@@@@@@@@@@@@@%**++++++==-:      \n"
        " -=============.*@@@@%%%%@@@@@@@@@@@@@@@@@@@@@@@%**+++++++      \n"
        " ============+: -@@@@%@@@@@@@@@@%%%%%%%@%%@@@@@@@##*+++:        \n"
        "  =======++++=#%@@@%@@@@@@%%@%%%%%%%%%%%%%%@@%@@%+ ..           \n"
        "  .-+*+****=-#@@@@@@@@@%%%%%%%%%%%%#%%%%%%%%%%@@%#              \n");
}
