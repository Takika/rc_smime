RoundCube S/MIME verification plugin - rc_smime
===============================================

Roundcube webmail plugin to verify S/MIME messages.  

This is a fork of rc_smime with updated design/gfx (to look more nice in my opinion) and fixes by Robert Currie (https://github.com/rob-c) that made it work with Roundcube 1.5 and PHP8.  
Also i've added Polish translation.
  
Installation
============
- Clone from github:
    HomeRoundCubeFolder/plugins$ git clone [https://github.com/nicrame/rc_smime.git](https://github.com/nicrame/rc_smime.git)
    
(Or use composer
     HomeRoundCubeFolder$ composer require nicrame/rc_smime:master
     
 NOTE: Answer **N** when composer ask you about plugin activation)

- Activate the plugin into HomeRoundCubeFolder/config/config.inc.php:
    $config['plugins'] = array('rc_smime');
