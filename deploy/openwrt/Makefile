include $(TOPDIR)/rules.mk

PKG_NAME:=p2wlan
PKG_VERSION:=$(P2WLAN_VERSION)
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=P2WLAN contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

# The driver builds static baseline-CPU musl binaries from the Git checkout,
# then uses the official SDK to create the native package and lifecycle hooks.
# This avoids rebuilding the entire Rust/LLVM host toolchain inside each SDK.
include $(INCLUDE_DIR)/package.mk

define Package/p2wlan
  SECTION:=net
  CATEGORY:=Network
  TITLE:=P2WLAN encrypted virtual LAN node
  URL:=https://github.com/yhan-sun/p2wlan
  DEPENDS:=+kmod-tun +ip-full +jsonfilter
  PKGARCH:=$(P2WLAN_PACKAGE_ARCH)
endef

define Package/p2wlan/description
  P2WLAN CLI and daemon with Linux TUN support, managed by procd.
  Configure and authenticate with the CLI before starting the service.
endef

define Package/p2wlan/conffiles
/etc/config/p2wlan
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(P2WLAN_BINARY_DIR)/p2wlan $(PKG_BUILD_DIR)/
	$(CP) $(P2WLAN_BINARY_DIR)/p2wlan-daemon $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/p2wlan/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/p2wlan $(1)/lib/upgrade/keep.d
	chmod 0700 $(1)/etc/p2wlan
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/p2wlan $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/p2wlan-daemon $(1)/usr/bin/
	$(INSTALL_BIN) ./files/p2wlan.init $(1)/etc/init.d/p2wlan
	$(INSTALL_CONF) ./files/p2wlan.config $(1)/etc/config/p2wlan
	$(INSTALL_DATA) ./files/p2wlan.keep $(1)/lib/upgrade/keep.d/p2wlan
endef

$(eval $(call BuildPackage,p2wlan))
