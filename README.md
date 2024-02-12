# Cisco Meraki automation to simplify install and operations

## Create a virtual enviroment

Linux and pyATS Required
The following instructions are based on Windows WSL2 and Ubuntu however any flavour of Linux will work with possibly slightly different commands.
Confirm Python 3.8.10 is installed


``` bash
     python --version
Python 3.8.10
```

## Create a virtual enviroment

``` bash
    
$ sudo apt install python3-venv
$ python3 -m venv merak
$ source meraki/bin/activate
(meraki)$

```

## Clone the repository

``` bash
git clone https://github.com/Jair0so/rid_meraki.git

cd rid_meraki
```
## Install all dependencies

``` bash
pip install -r requirements.txt
```
## Create enviroment variable

Go to Meraki Dashboard, on the left side select Organization, then API & Webhooks

Once in the new page click on the Overview tab and click Generate API key it will take you to the Personal API keys

Click on Generate API key, copy the key in a sefe location, do not share with anyone. 

Now you are ready to create a new enviroment variable

``` bash
export MERAKI_DASHBOARD_API_KEY='your_API_key'
```

## How to use it

``` bash
(meraki)$ python rid_meraki.py 

```
it will list all organizations you have access to

``` bash
           Organizations           
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID      ┃ Name                  ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ 467623  │ This_is_a_test        │
└─────────┴───────────────────────┘
Enter the ID of the organization: 

Select an option:
1. Provide all devices in the network
2. Provide all access points
3. Create a new network
4. Bind hardware to a network
5. Default site creation
6. Vlan creation
Enter your choice [1/2/3/4/5/6]: 1

MX68 - XXXX-XXXX-XXXX
MR36 - YYYY-YYYY-YYYY
MR36 - ZZZZ-ZZZZ-ZZZZ

```

## Configuration

For configuration section make sure you update the YAML file with the configuration requirements.