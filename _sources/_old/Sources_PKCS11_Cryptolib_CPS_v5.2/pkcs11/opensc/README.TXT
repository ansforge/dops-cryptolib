
==========================================================================================================
PKCS#11 Library for the French healthcare professional's card (CPS3) based on opensc v0.11.12 - 18-12-2009
==========================================================================================================


This library is provided under the terms of the LGPL license (LICENSE.TXT)

Copyright (C) 2010-2016  ASIP Santé

This library is free software; you can re-distribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA


=======================================
    BUILDING
=======================================

 ---- WINDOWS 32/64bit Project ---- 
Visual Studio 2015 project: ./win32/cps3_pkcs11.sln 

 ---- MAC OS X Universal Library 32/64bit ---- 
XCode 8.0 project: ./macosx/cps3pkcs11.xcodeproj 

 ---- Linux 32 bit ---- 
script file: buildall.sh

 ---- Linux 64 bit ---- 
script file: buildall64.sh


=======================================
    LOG ACTIVATION
=======================================

 ---- On Windows in the Registry ----

[HKEY_CURRENT_USER\Software\ASIP Sante\PKCS11]
"Traces"=dword:00000001
"Debug"=dword:0000000a


 ---- On MAC OX X with a configuration File  ----
Copy file ./macosx/cps3_pkcs11.conf into /Library/Preferences/santesocial/CPS/


 ---- On Linux with a configuration File  ----
Copy file ./linux/cps3_pkcs11.conf into /etc/opt/santesocial/CPS/

