RoundCube S/MIME verification plugin - rc_smime
===============================================

Roundcube webmail plugin to verify S/MIME messages.  

Updated design/gfx and plish translation by @nicrame (https://github.com/nicram) and fixes by @kochichi (https://github.com/kochichi) that made it work with Roundcube 1.5 and PHP8.  
  
Installation
============
- Clone from github:
    HomeRoundCubeFolder/plugins$ git clone [https://github.com/Takika/rc_smime.git](https://github.com/Takika/rc_smime.git)
    
- Or use composer
     HomeRoundCubeFolder$ composer require takika/rc_smime:dev-master
     
 NOTE: Answer **N** when composer ask you about plugin activation)

- Activate the plugin into HomeRoundCubeFolder/config/config.inc.php:
    $config['plugins'] = array('rc_smime');
