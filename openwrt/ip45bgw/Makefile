#
# Copyright (C) 2013 Jeff <jeff@openwrt.org>
# Copyright (C) 2013 Tomas Podermanski <tpoder@cis.vutbr.cz>
#
# This is free software, licensed under the Apache 2 license.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ip45bgw
PKG_VERSION:=0
PKG_RELEASE:=118

PKG_SOURCE:=ipt_$(PKG_NAME)-$(PKG_VERSION).$(PKG_RELEASE).tar.gz
PKG_SOURCE_URL:=http://www.ip45.org/packages/source/
PKG_BUILD_DIR:=$(BUILD_DIR)/ipt_$(PKG_NAME)-$(PKG_VERSION).$(PKG_RELEASE)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel-defaults.mk

define Package/ip45bgw/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  DEFAULT:=m 
  TITLE:=Border Gateway (BGW) iptables module for IP45
  URL:=http://ip45.org/
  DEPENDS:=iptables
endef

define Package/ip45bgw
$(call Package/ip45bgw/Default)
  TITLE:=Border Gateway (BGW) iptables module for IP45
  MAINTAINER:=Tomas Podermanski <tpoder@cis.vutbr.cz>
endef

define Package/ip45bgw/description
  The package contains the ip45bgw kernel module for performing 
  IP45 Border Gateway Operation on the router. 
endef

define Build/Prepare
	$(call Build/Prepare/Default,)
	$(CP) $(PKG_BUILD_DIR)/makefile.kernel $(PKG_BUILD_DIR)/Makefile
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -pipe -D_INIT=libipt_ip45bgw_init -DPIC -fPIC -g -O2 \
		-shared -o $(PKG_BUILD_DIR)/libipt_ip45bgw.so $(PKG_BUILD_DIR)/libipt_ip45bgw.c
	$(MAKE) $(KERNEL_MAKEOPTS) SUBDIRS="$(PKG_BUILD_DIR)" modules
endef

define Package/ip45bgw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libipt_ip45bgw.so $(1)/usr/lib
	$(INSTALL_DIR) $(1)/lib/modules/$(LINUX_VERSION)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipt_ip45bgw.ko $(1)/lib/modules/$(LINUX_VERSION)
endef


$(eval $(call BuildPackage,ip45bgw))
#$(eval $(call KernelPackage,ip45bgw))
