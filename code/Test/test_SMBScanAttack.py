import unittest.mock as mock

import Test.ID2TAttackTest as Test

sha_default = '68eeaed9682bdd63581cfe55c314ca3c024b487ebcbc2c539453b0ec85bcb21e'
sha_dest_mac_only = '3b79e327a96dd6c8b49193cee794e813cfd6be50dd50c66e9082d984e8e91fc4'
sha_multiple_victims_macos = '35c94ff8efd0958c39807e57477e967fdc100f9e12a68dcb6b368bb7de76056b'
sha_one_victim_linux = 'aeb46ccd80e3862856931dc1d430e5a5e126deef5b291f9581735952f61facad'
sha_port_shuffle = '9d124e51966324528e335e43a2a7bb635b20427a76337a5e1c91d56cc152acab'
sha_smb2 = 'a3b3eebb41da0c8a8b6fd55855bdec44e30d2152947652113d496ec8f2aa60d9'
sha_ip_src_shuffle = '79d86343ec9334cd750a8383f233e619142863c7010e48c28c4bc10a574c67e7'
sha_victim_range_winxp_hosting = '7b3c001c9aab3d1c3a76c59efbaf197a4ea8aed7655a12f3e06d3e88d0fd5689'

# TODO: improve coverage


class UnitTestSMBScan(Test.ID2TAttackTest):
    def test_smbscan_default(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack']], sha_default)

    def test_smbscan_one_victim_linux(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="linux"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.10']],
                               sha_one_victim_linux)

    def test_smbscan_victim_range_winxp_hosting(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="winxp"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5']], sha_victim_range_winxp_hosting)

    def test_smbscan_multiple_victims_macos(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="macos"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1',
                                 'ip.dst=192.168.178.10,192.168.178.15,192.168.178.20',
                                 'hosting.ip=192.168.178.15,192.168.178.20']], sha_multiple_victims_macos)

    def test_smbscan_invalid_smb_version(self):
        with self.assertRaises(SystemExit):
            self.checksum_test([['SMBScanAttack', 'protocol.version=42']], 'somehash')

    def test_smbscan_port_shuffle(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5', 'port.src.shuffle=false']], sha_port_shuffle)

    def test_smbscan_dest_mac_only(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'mac.dst=00:0C:29:9C:70:64']],
                               sha_dest_mac_only)

    def test_smbscan_src_ip_shuffle(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="win7"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5', 'ip.src.shuffle=True']], sha_ip_src_shuffle)

    def test_smbscan_smb2(self):
        with mock.patch("ID2TLib.Utility.get_rnd_os", return_value="linux"):
            self.checksum_test([['SMBScanAttack', 'ip.src=192.168.178.1', 'ip.dst=192.168.178.5-192.168.178.10',
                                 'hosting.ip=192.168.178.5', 'protocol.version=2.1', 'hosting.version=2.1']], sha_smb2)

    def test_smbscan_order(self):
        self.order_test([['SMBScanAttack']])
