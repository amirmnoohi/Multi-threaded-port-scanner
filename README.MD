# **Port Scanner Project** [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://gitlab.com/limner/network-project-3962)

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Django.svg)
![Build](https://img.shields.io/bitbucket/pipelines/atlassian/adf-builder-javascript/task/SECO-2168.svg)
![PyPI - Status](https://img.shields.io/pypi/status/Django.svg)
![Read the Docs](https://img.shields.io/readthedocs/pip.svg)

This is Port Scanner with only python like nmap.

Version : 1.6

Build : Passing

Author : Amir Masoud Noohi

Language : Python Both 2.7 - 3.7.0




# **PreRequirements**

For This Project You Need below Requirements :
- pyhon3

```shell
$ apt install python3
```

# **Usage**
## Step0 : Cloning

First of All Clone the Project : 

```shell
$ git clone https://gitlab.com/limner/network-project-3962.git
$ cd network-project-3962/2
```

## Step1 : Run Code

To run this code We need 4 arguments : 

1- '-t' | '--target' : Address of Target ip or hostname : google.com

2- '-p' | '--port' : Range of port for scanning : 0-200

3- '-s' | '--scan' : Scan Type : CS(Connect Scan) - AS(Ack Scan) - SS(SYN Scan) - FS(FIN Scan) - WS(Windows Scan)

4- '-d' | '--delay' : Delay for checking accurately all received packets Default : 2 Second

for example :
```shell
$ python3 main.py -t www.highhost.org -p 0-100 -s CS -d 3
```

# **OUTPUT**
the output is list of all open | filtered | unfiltered | closed ports based on scan type




# **Run-Time**
![RUN GIF](https://highhost.org/gif-video/2.gif)

# **Files**

- <a href="https://gitlab.com/limner/network-project-3962/blob/master/2/main.py" target="_blank">`/main.py`</a> : This is Main File
- <a href="https://gitlab.com/limner/network-project-3962/blob/master/2/services.py" target="_blank">`/services.py`</a> : This is list of all ports with service name
- <a href="https://gitlab.com/limner/network-project-3962/blob/master/2/extra.py" target="_blank">`/extra.py`</a> : This is sniffer code that is embeded in main.py


# **Support**

Reach out to me at one of the following places!

- Telegram at <a href="https://t.me/amirmnoohi" target="_blank">@amirmnoohi</a>
- Gmail at <a href="mailto:highlimner@gmail.com" target="_blank">highlimner@gmail.com</a>

# **License**

[![License](https://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Copyright 2018 © <a href="https://gitlab.com/limner/network-project-3962" target="_blank">Network Project</a>.
