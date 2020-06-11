# Turbo Intruder Scripts
This is just a repo where I keep my own personal Turbo Intruder helper scripts.

# DesyncAttack_CLTE.py and DesyncAttack_TECL.py
These scripts I use to create Request Smuggling Desync payloads for CLTE and TECL style attacks.
How to use:
1) Open Burp
2) Open a Repeater tab to your target
3) Right click your request and "Send to Turbo Intruder"
4) Completely replace the script pane (bottom pane) with DesyncAttack_CLTE.py or DesyncAttack_TECL.py
5) The top (request) pane is not needed and ignored, the script creates its own requests
6) Fill out all the attack parameters for the attack (documentation inside the script)
7) click "Attack"

# License
These scripts are released under MIT license. See [LICENSE](https://github.com/defparam/tiscripts/blob/master/LICENSE).
