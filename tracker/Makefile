include $(TOPDIR)/rules.mk

PKG_NAME:=tracker
PKG_RELEASE:=1
PKG_VERSION:=1.0.0

include $(INCLUDE_DIR)/package.mk

define Package/tracker
	CATEGORY:=Base system
	TITLE:=Tracker
	DEPENDS:=+libopenssl +libcurl +libuci
endef

define Package/tracker/description
	Process tracker
endef

define Package/tracker/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tracker $(1)/usr/bin
	$(INSTALL_BIN) ./files/tracker.init $(1)/etc/init.d/tracker
	$(INSTALL_CONF) ./files/tracker.config $(1)/etc/config/tracker
endef

$(eval $(call BuildPackage,tracker))