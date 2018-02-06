# -*- mode: ruby -*-
# # vi: set ft=ruby :

require 'fileutils'
require 'open-uri'
require 'tempfile'
require 'yaml'
Vagrant.require_version ">= 1.7.4"

DRIVERLETTERS = ('b'..'z').to_a
# copy from a platform build of heketi-cli
HEKETI_CLI = 'bin/heketi-cli'

$update_channel = "stable"
$controller_count = 1
$controller_vm_memory = 2048

$worker_count = 1
$worker_vm_cpus = 1
$worker_vm_memory = 2048

$loadbalancer_count = 1
$loadbalancer_vm_cpus = 1
$loadbalancer_vm_memory = 2048

$storage_nodes = 2
$storage_disks = 4
$storage_vm_cpus = 2
$storage_vm_memory = 2048

if $worker_vm_memory < 1024
  puts "Workers should have at least 1024 MB of memory"
end

CONTROLLER_USER_DATA_PATH = File.expand_path("./cluster/user-data-controller")
WORKER_USER_DATA_PATH = File.expand_path("./cluster/user-data-worker")
LOADBALANCER_USER_DATA_PATH = File.expand_path("./cluster/user-data-loadbalancer")
KUBECONFIG_PATH = File.expand_path("cluster/auth/kubeconfig")
CA_CERT_PATH = File.expand_path("cluster/tls/ca.crt")
ETCD_CLI_CERT_GLOB = File.expand_path("cluster/tls/etcd-*")
ETCD_CERT_GLOB = File.expand_path("cluster/tls/etcd/*")
STORAGE_USER_DATA_PATH = File.expand_path("./cluster/user-data-storage")

PRIVATE_IP_PREFIX = "172.17.4"
def storageIP(num)
  return "#{PRIVATE_IP_PREFIX}.#{num+226}"
end

def etcdIP(num)
  return "#{PRIVATE_IP_PREFIX}.#{num+51}"
end

def controllerIP(num)
  return "#{PRIVATE_IP_PREFIX}.#{num+101}"
end

def workerIP(num)
  return "#{PRIVATE_IP_PREFIX}.#{num+201}"
end

def loadbalancerIP(num)
  return "#{PRIVATE_IP_PREFIX}.#{num+224}"
end

$self_host_etcd = true if ENV['SELF_HOST_ETCD'] == "true"
if !$self_host_etcd
    $etcd_count = 1
    $etcd_vm_memory = 512
    ETCD_CLOUD_CONFIG_PATH = File.expand_path("./etcd-cloud-config.yaml")
    etcdIPs = [*0..$etcd_count-1].map{ |i| etcdIP(i) }
    initial_etcd_cluster = etcdIPs.map.with_index{ |ip, i| "e#{i}=https://#{ip}:2380" }.join(",")
end

Vagrant.configure("2") do |config|
  # always use Vagrant's insecure key
  config.ssh.insert_key = false
  config.env.enable

  config.vm.box = "coreos-%s" % $update_channel
  config.vm.box_version = ">= 766.0.0"
  config.vm.box_url = "http://%s.release.core-os.net/amd64-usr/current/coreos_production_vagrant.json" % $update_channel

  ["vmware_fusion", "vmware_workstation"].each do |vmware|
    config.vm.provider vmware do |v, override|
      override.vm.box_url = "http://%s.release.core-os.net/amd64-usr/current/coreos_production_vagrant_vmware_fusion.json" % $update_channel
    end
  end

  config.vm.provider :virtualbox do |v|
    # On VirtualBox, we don't have guest additions or a functional vboxsf
    # in CoreOS, so tell Vagrant that so it can be smarter.
    v.check_guest_additions = false
    v.functional_vboxsf     = false
  end

  # plugin conflict
  if Vagrant.has_plugin?("vagrant-vbguest") then
    config.vbguest.auto_update = false
  end

  ["vmware_fusion", "vmware_workstation"].each do |vmware|
    config.vm.provider vmware do |v|
      v.vmx['numvcpus'] = 1
      v.gui = false
    end
  end

  config.vm.provider :virtualbox do |vb|
    vb.cpus = 1
    vb.gui = false
  end

  if !$self_host_etcd
    (0..$etcd_count-1).each do |i|
      config.vm.define vm_name = "e%d" % i do |etcd|

        data = File.read(ETCD_CLOUD_CONFIG_PATH)
        data = data.gsub("{{ETCD_NODE_NAME}}", vm_name)
        data = data.gsub("{{ETCD_INITIAL_CLUSTER}}", initial_etcd_cluster)
        etcd_config_file = Tempfile.new('etcd_config')
        etcd_config_file.write(data)
        etcd_config_file.close

        etcd.vm.hostname = vm_name

        ["vmware_fusion", "vmware_workstation"].each do |vmware|
          etcd.vm.provider vmware do |v|
            v.vmx['memsize'] = $etcd_vm_memory
          end
        end

        etcd.vm.provider :virtualbox do |vb|
          vb.memory = $etcd_vm_memory
          vb.name = vm_name
        end

        etcd.vm.network :private_network, ip: etcdIP(i)

        etcd.vm.provision :file, source: etcd_config_file.path, destination: "/tmp/vagrantfile-user-data"
        etcd.vm.provision :shell, inline: "mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/", privileged: true

        etcd.vm.provision :shell, :inline => "mkdir -p /etc/etcd/tls", :privileged => true
        Dir.glob(ETCD_CLI_CERT_GLOB) do |etcd_cert_file|
          etcd.vm.provision :file, :source => etcd_cert_file, :destination => "/tmp/#{File.basename(etcd_cert_file)}"
          etcd.vm.provision :shell, :inline => "mv /tmp/#{File.basename(etcd_cert_file)} /etc/etcd/tls/", :privileged => true
        end
        etcd.vm.provision :shell, :inline => "mkdir -p /etc/etcd/tls/etcd", :privileged => true
        Dir.glob(ETCD_CERT_GLOB) do |etcd_cert_file|
          etcd.vm.provision :file, :source => etcd_cert_file, :destination => "/tmp/#{File.basename(etcd_cert_file)}"
          etcd.vm.provision :shell, :inline => "mv /tmp/#{File.basename(etcd_cert_file)} /etc/etcd/tls/etcd/", :privileged => true
        end
        etcd.vm.provision :shell, :inline => "chown -R etcd:etcd /etc/etcd", :privileged => true
        etcd.vm.provision :shell, :inline => "chmod -R u=rX,g=,o= /etc/etcd", :privileged => true
      end
    end
  end


  (0..$controller_count-1).each do |i|
    config.vm.define vm_name = "c%d" % i do |controller|
      controller.vm.hostname = vm_name

      ["vmware_fusion", "vmware_workstation"].each do |vmware|
        controller.vm.provider vmware do |v|
          v.vmx['memsize'] = $controller_vm_memory
        end
      end

      controller.vm.provider :virtualbox do |vb|
        vb.memory = $controller_vm_memory
        vb.name = vm_name
      end

      controller.vm.network :private_network, ip: controllerIP(i)

      controller.vm.provision :shell, :inline => "mkdir -p /opt/bin", :privileged => true
      controller.vm.provision :file, source: HEKETI_CLI, destination: "/tmp/heketi-cli"
      controller.vm.provision :shell, :inline => "mv /tmp/heketi-cli /opt/bin/heketi-cli", :privileged => true

      controller.vm.provision :file, source: CONTROLLER_USER_DATA_PATH, destination: "/tmp/vagrantfile-user-data"
      controller.vm.provision :shell, inline: "mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/", privileged: true

      controller.vm.provision :shell, :inline => "mkdir -p /etc/kubernetes", :privileged => true

      controller.vm.provision :file, :source => KUBECONFIG_PATH, :destination => "/tmp/kubeconfig"
      controller.vm.provision :shell, :inline => "mv /tmp/kubeconfig /etc/kubernetes/kubeconfig", :privileged => true

      controller.vm.provision :file, :source => CA_CERT_PATH, :destination => "/tmp/ca.crt"
      controller.vm.provision :shell, :inline => "mv /tmp/ca.crt /etc/kubernetes/ca.crt", :privileged => true
    end
  end

  (0..$worker_count-1).each do |i|
    config.vm.define vm_name = "w%d" % i do |worker|
      worker.vm.hostname = vm_name

      ["vmware_fusion", "vmware_workstation"].each do |vmware|
        worker.vm.provider vmware do |v|
          v.vmx['memsize'] = $worker_vm_memory
        end
      end

      worker.vm.provider :virtualbox do |vb|
        vb.cpus = $worker_vm_cpus
        vb.memory = $worker_vm_memory
        vb.name = vm_name
      end

      worker.vm.network :private_network, ip: workerIP(i)

      worker.vm.provision :shell, :inline => "mkdir -p /opt/bin", :privileged => true
      worker.vm.provision :file, source: HEKETI_CLI, destination: "/tmp/heketi-cli"
      worker.vm.provision :shell, :inline => "mv /tmp/heketi-cli /opt/bin/heketi-cli", :privileged => true

      worker.vm.provision :file, source: WORKER_USER_DATA_PATH, destination: "/tmp/vagrantfile-user-data"
      worker.vm.provision :shell, inline: "mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/", privileged: true

      worker.vm.provision :shell, :inline => "mkdir -p /etc/kubernetes", :privileged => true

      worker.vm.provision :file, :source => KUBECONFIG_PATH, :destination => "/tmp/kubeconfig"
      worker.vm.provision :shell, :inline => "mv /tmp/kubeconfig /etc/kubernetes/kubeconfig", :privileged => true

      worker.vm.provision :file, :source => CA_CERT_PATH, :destination => "/tmp/ca.crt"
      worker.vm.provision :shell, :inline => "mv /tmp/ca.crt /etc/kubernetes/ca.crt", :privileged => true
    end
  end

  (0..$loadbalancer_count-1).each do |i|
    config.vm.define vm_name = "lb%d" % i do |loadbalancer|
      loadbalancer.vm.hostname = vm_name

      ["vmware_fusion", "vmware_workstation"].each do |vmware|
        loadbalancer.vm.provider vmware do |v|
          v.vmx['memsize'] = $loadbalancer_vm_memory
        end
      end

      loadbalancer.vm.provider :virtualbox do |vb|
        vb.cpus = $loadbalancer_vm_cpus
        vb.memory = $loadbalancer_vm_memory
        vb.name = vm_name
      end

      loadbalancer.vm.network :private_network, ip: loadbalancerIP(i)
      loadbalancer.vm.network :public_network, bridge: "wlan0"

      loadbalancer.vm.provision :shell, :inline => "mkdir -p /opt/bin", :privileged => true
      loadbalancer.vm.provision :file, source: HEKETI_CLI, destination: "/tmp/heketi-cli"
      loadbalancer.vm.provision :shell, :inline => "mv /tmp/heketi-cli /opt/bin/heketi-cli", :privileged => true

      loadbalancer.vm.provision :file, source: LOADBALANCER_USER_DATA_PATH, destination: "/tmp/vagrantfile-user-data"
      loadbalancer.vm.provision :shell, inline: "mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/", privileged: true

      loadbalancer.vm.provision :shell, :inline => "mkdir -p /etc/kubernetes", :privileged => true

      loadbalancer.vm.provision :file, :source => KUBECONFIG_PATH, :destination => "/tmp/kubeconfig"
      loadbalancer.vm.provision :shell, :inline => "mv /tmp/kubeconfig /etc/kubernetes/kubeconfig", :privileged => true

      loadbalancer.vm.provision :file, :source => CA_CERT_PATH, :destination => "/tmp/ca.crt"
      loadbalancer.vm.provision :shell, :inline => "mv /tmp/ca.crt /etc/kubernetes/ca.crt", :privileged => true
    end
  end

  (0..$storage_nodes-1).each do |n|
    config.vm.define vm_name = "gfs%d" % n do |storage|
      storage.vm.hostname = vm_name
      storage.vm.provider :virtualbox do |vb|
        vb.memory = $storage_vm_memory
        vb.cpus = $storage_vm_cpus
        vb.name = vm_name
      end
      storage.vm.provision :shell, :inline => "mount -a || true; ls -al /dev/sd[a-z]", :privileged => true
      storage.vm.provision :shell, privileged: true, inline: "/sbin/swapoff --all"

      storage.vm.network :private_network, ip: storageIP(n)


      storage.vm.provision :shell, :inline => "mkdir -p /opt/bin", :privileged => true
      storage.vm.provision :file, source: HEKETI_CLI, destination: "/tmp/heketi-cli"
      storage.vm.provision :shell, :inline => "mv /tmp/heketi-cli /opt/bin/heketi-cli", :privileged => true

      storage.vm.provision :shell, inline: "mkdir -p /gfs/vol0", privileged: true
      storage.vm.provision :file, source: STORAGE_USER_DATA_PATH, destination: "/tmp/vagrantfile-user-data"
      storage.vm.provision :shell, inline: "mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/", privileged: true

      storage.vm.provision :shell, :inline => "mkdir -p /etc/kubernetes", :privileged => true

      storage.vm.provision :file, :source => KUBECONFIG_PATH, :destination => "/tmp/kubeconfig"
      storage.vm.provision :shell, :inline => "mv /tmp/kubeconfig /etc/kubernetes/kubeconfig", :privileged => true

      storage.vm.provision :file, :source => CA_CERT_PATH, :destination => "/tmp/ca.crt"
      storage.vm.provision :shell, :inline => "mv /tmp/ca.crt /etc/kubernetes/ca.crt", :privileged => true
      storage.vm.provision "shell", :privileged => true, inline: <<-SHELL
         modprobe dm_thin_pool
         modprobe fuse
         echo "heketi:x:996:996:heketi user:/var/lib/heketi:/sbin/nologin" >> /etc/passwd
         echo "heketi:x:996:"                                              >> /etc/group
         mkdir -p /var/lib/heketi/{.ssh,config} /etc/heketi/{.ssh,config}
         chown heketi:heketi -R /var/lib/heketi /etc/heketi
         chmod 0755 /var/lib/heketi /etc/heketi
         chmod 0700 /var/lib/heketi/.ssh /etc/heketi/.ssh
      SHELL
    end
  end

  (0..$storage_nodes-1).each do |n|
    config.vm.define vm_name = "gfs%d" % n do |storage|
      # storage.vm.provision :file, :source => "heketi-configure.sh", :destination => "/tmp/heketi-configure.sh"
      # storage.vm.provision :shell, :inline => "mkdir -p /var/lib/heketi; mv /tmp/heketi-configure.sh /var/lib/heketi/heketi-configure.sh; chmod +x /var/lib/heketi/heketi-configure.sh;", :privileged => true

      storage.vm.provider :virtualbox do |vb|
        unless File.exist?("gfs-#{n}-0.vdi")
          vb.customize ["storagectl", :id,"--name", "VBoxSATA", "--add", "sata"]
        end
        (0..$storage_disks-1).each do |d|
          unless File.exist?("gfs-#{n}-#{d}.vdi")
            vb.customize [ "createmedium", "--filename", "gfs-#{n}-#{d}.vdi", "--size", 512*1024 ]
            vb.customize [ "storageattach", :id, "--storagectl", "VBoxSATA", "--port", 3+d, "--device", 0, "--type", "hdd", "--medium", "gfs-#{n}-#{d}.vdi" ]
          end
          # storage.vm.provision :shell, :inline => "mkfs.xfs -i size=1024 /dev/sd#{DRIVERLETTERS[d]} 2>/dev/null || true", :privileged => true
          # storage.vm.provision :shell, :inline => "mkdir -p /var/data/brick#{d}", :privileged => true
          # storage.vm.provision :shell, :inline => "touch /etc/fstab", :privileged => true
          # storage.vm.provision :shell, :inline => "grep -q /dev/sd#{DRIVERLETTERS[d]} /etc/fstab || echo '/dev/sd#{DRIVERLETTERS[d]} /var/data/brick#{d} xfs defaults 1 2' >> /etc/fstab", :privileged => true
        end
      end
      storage.vm.provision "shell", :privileged => true, inline: <<-SHELL
         lvmconfig --type default --withcomments > /etc/lvm/lvm.conf
         systemctl enable lvm2-lvmetad.service
         systemctl enable lvm2-lvmetad.socket
         systemctl start lvm2-lvmetad.service
         systemctl start lvm2-lvmetad.socket
      SHELL
    end
  end

  ######## (1..$storage_nodes).each do |n|
  ########   config.vm.define vm_name = "gfs%d" % n do |storage|
  ########     storage.vm.provider :virtualbox do |vb|
  ########       vb.memory = $storage_vm_memory
  ########       vb.cpus = $storage_vm_cpus
  ########       vb.name = vm_name
  ########       unless File.exist?("gfs-#{n}-0.vdi")
  ########         vb.customize ["storagectl", :id,"--name", "VBoxSATA", "--add", "sata"]
  ########       end
  ########       (0..$storage_disks-1).each do |d|
  ########         unless File.exist?("gfs-#{n}-#{d}.vdi")
  ########           vb.customize [ "createmedium", "--filename", "gfs-#{n}-#{d}.vdi", "--size", 512*1024 ]
  ########           vb.customize [ "storageattach", :id, "--storagectl", "VBoxSATA", "--port", 3+d, "--device", 0, "--type", "hdd", "--medium", "gfs-#{n}-#{d}.vdi" ]
  ########         end
  ########         storage.vm.provision :shell, :inline => "mkfs.xfs -i size=1024 /dev/sd#{DRIVERLETTERS[d]} 2>/dev/null || true", :privileged => true
  ########         storage.vm.provision :shell, :inline => "mkdir -p /var/data/brick#{d}", :privileged => true
  ########         storage.vm.provision :shell, :inline => "touch /etc/fstab", :privileged => true
  ########         storage.vm.provision :shell, :inline => "grep -q /dev/sd#{DRIVERLETTERS[d]} /etc/fstab || echo '/dev/sd#{DRIVERLETTERS[d]} /var/data/brick#{d} xfs defaults 1 2' >> /etc/fstab", :privileged => true
  ########       end
  ########     end
  ########   end
  ######## end
end
