qemu-system-aarch64 -machine virt,gic-version=3,iommu=smmuv3 \
-bios ./QEMU_EFI.fd \
-enable-kvm -cpu host -m 1024 \
-kernel ./linux-kernel-warpdrive/arch/arm64/boot/Image \
-initrd ./rootfs.cpio.gz -nographic -append \
"rdinit=init console=ttyAMA0 earlycon=pl011,0x9000000 acpi=force" \
-device virtio-9p-pci,fsdev=p9fs,mount_tag=p9 \
-fsdev local,id=p9fs,path=p9root,security_model=mapped

#-device vfio-pci,host=0000:75:00.1 \
#-device virtio-9p-pci,fsdev=p9fs,mount_tag=p9 \
#-fsdev local,id=p9fs,path=p9root,security_model=mapped \
#https://blog.csdn.net/scarecrow_byr/article/details/86438011
#https://blog.csdn.net/scarecrow_byr/article/details/40707323
