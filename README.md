Synopsis
--------

SAMAuth4OpenVPN [group] [logging] [log-directory]

Description
-----------

`SAMAuth4OpenVPN` is an authentication plugin for OpenVPN that performs authentication of local (non Active-Directory) Windows user accounts.

Using `SAMAuth4OpenVPN`
----------------------

1. Copy the `SAMAuth4OpenVPN.exe` file to the `bin` directory of your server's OpenVPN installation. The default location is `C:\Program Files\OpenVPN\bin\`.

2. Set up your respective .ovpn configuration file to invoke `SAMAuth4OpenVPN` to perform authentication whenever a client connects:

    1. Open the respective .ovpn file (for ex. *server.ovpn* or how you named it). The default location for configuration files is `C:\Program Files\OpenVPN\config\`.

 2. Add the following lines to the end of the file:

     **script-security 3**  
     **auth-user-pass-verify "C:/Progra~1/OpenVPN/bin/SAMAuth4OpenVPN.exe \"VPN Users\" true ../log/auth" via-env**

     This will set up `SAMAuth4OpenVPN` so that Windows user accounts must be members of the local group *VPN Users* in order to pass authentication. It will also generate logs in `C:\Program Files\OpenVPN\log\auth\` for each authentication attempt. Of course, if you installed OpenVPN to a different location, adjust the above path accordingly.

 3. This step is optional. If you wish to disable client-certificate authentication, add the following additional lines to the file:

      **client-cert-not-required**  
      **username-as-common-name**

3. Restart the OpenVPN server/service.

4. Configure your client's .ovpn configuration file to ask for a username and password upon connect by adding the following line to the the client's .ovpn file:

  **auth-user-pass**  
  **auth-retry interact**


For an explanation of the available command-line options, please see the next section.

Options
-------

The program optionally accepts up to 3 command-line arguments.

1. The first argument is the name of a local Windows group the respective Windows user accounts must be part of in order to pass authentication. If `SAMAuth4OpenVPN` is invoked without any arguments, the name of this group defaults to `VPN Users`.

 If you want to drop the group requirement, you can pass the empty string for this argument, i.e. `\"\"`.

2. The second argument determines whether log entries should be written. Specifying anything other than `false` for this argument evaluates to `true` and enables logging.

 Log files follow the naming scheme dd-mm-yyyy.log and roll over by date.

3. The third argument specifies the directory where log files will be stored. This can be an absolute path or a path that is relative to the location of the `SAMAuth4OpenVPN.exe` file.

 If this argument is omitted and logging is enabled, log files are written to the same directory where `SAMAuth4OpenVPN.exe` is located.


Authors
-------

© 2015 Torben Könke (torben dot koenke at gmail dot com).

License
-------

This program is released under the GNU General Public License, version 2.
