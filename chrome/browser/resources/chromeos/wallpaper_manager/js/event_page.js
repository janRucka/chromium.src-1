// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var WALLPAPER_PICKER_WIDTH = 574;
var WALLPAPER_PICKER_HEIGHT = 420;

var wallpaperPickerWindow;

var surpriseWallpaper = null;

function SurpriseWallpaper() {
}

/**
 * Gets SurpriseWallpaper instance. In case it hasn't been initialized, a new
 * instance is created.
 * @return {SurpriseWallpaper} A SurpriseWallpaper instance.
 */
SurpriseWallpaper.getInstance = function() {
  if (!surpriseWallpaper)
    surpriseWallpaper = new SurpriseWallpaper();
  return surpriseWallpaper;
};

/**
 * Tries to change wallpaper to a new one in the background. May fail due to a
 * network issue.
 */
SurpriseWallpaper.prototype.tryChangeWallpaper = function() {
  var self = this;
  var onFailure = function(status) {
    if (status != 404)
      self.fallbackToLocalRss_();
    else
      self.updateRandomWallpaper_();
  };
  // Try to fetch newest rss as document from server first. If the requested
  // URL is not found (404 error), set a random wallpaper displayed in the
  // wallpaper picker. If any other error occurs, proceed with local copy of
  // rss.
  WallpaperUtil.fetchURL(Constants.WallpaperRssURL, 'document', function(xhr) {
    WallpaperUtil.saveToLocalStorage(Constants.AccessLocalRssKey,
        new XMLSerializer().serializeToString(xhr.responseXML));
    self.updateSurpriseWallpaper(xhr.responseXML);
  }, onFailure);
};

/**
 * Retries changing the wallpaper 1 hour later. This is called when fetching the
 * rss or wallpaper from server fails.
 * @private
 */
SurpriseWallpaper.prototype.retryLater_ = function() {
  chrome.alarms.create('RetryAlarm', {delayInMinutes: 60});
};

/**
 * Fetches the cached rss feed from local storage in the event of being unable
 * to download the online feed.
 * @private
 */
SurpriseWallpaper.prototype.fallbackToLocalRss_ = function() {
  var self = this;
  Constants.WallpaperLocalStorage.get(Constants.AccessLocalRssKey,
      function(items) {
    var rssString = items[Constants.AccessLocalRssKey];
    if (rssString) {
      self.updateSurpriseWallpaper(new DOMParser().parseFromString(rssString,
                                                                   'text/xml'));
    } else {
      self.updateSurpriseWallpaper();
    }
  });
};

/**
 * Starts to change wallpaper. Called after rss is fetched.
 * @param {Document=} opt_rss The fetched rss document. If opt_rss is null, uses
 *     a random wallpaper.
 */
SurpriseWallpaper.prototype.updateSurpriseWallpaper = function(opt_rss) {
  if (opt_rss) {
    var items = opt_rss.querySelectorAll('item');
    var date = new Date(new Date().toDateString()).getTime();
    for (var i = 0; i < items.length; i++) {
      item = items[i];
      var disableDate = new Date(item.getElementsByTagNameNS(
          Constants.WallpaperNameSpaceURI, 'disableDate')[0].textContent).
              getTime();
      var enableDate = new Date(item.getElementsByTagNameNS(
          Constants.WallpaperNameSpaceURI, 'enableDate')[0].textContent).
              getTime();
      var regionsString = item.getElementsByTagNameNS(
          Constants.WallpaperNameSpaceURI, 'regions')[0].textContent;
      var regions = regionsString.split(', ');
      if (enableDate <= date && disableDate > date &&
          regions.indexOf(navigator.language) != -1) {
        var self = this;
        this.setWallpaperFromRssItem_(item,
                                      function() {},
                                      function(status) {
                                        if (status != 404)
                                          self.retryLater_();
                                        else
                                          self.updateRandomWallpaper_();
                                      });
        return;
      }
    }
  }
  // No surprise wallpaper for today at current locale or fetching rss feed
  // fails. Fallback to use a random one from wallpaper server.
  this.updateRandomWallpaper_();
};

/**
 * Sets a new random wallpaper if one has not already been set today.
 * @private
 */
SurpriseWallpaper.prototype.updateRandomWallpaper_ = function() {
  var self = this;
  var onSuccess = function(items) {
    var dateString = new Date().toDateString();
    // At most one random wallpaper per day.
    if (items[Constants.AccessLastSurpriseWallpaperChangedDate] != dateString) {
      self.setRandomWallpaper_(dateString);
    }
  };
  WallpaperUtil.enabledSyncThemesCallback(function(syncEnabled) {
    if (syncEnabled) {
      Constants.WallpaperSyncStorage.get(
          Constants.AccessLastSurpriseWallpaperChangedDate, onSuccess);
    } else {
      Constants.WallpaperLocalStorage.get(
          Constants.AccessLastSurpriseWallpaperChangedDate, onSuccess);
    }
  });
};

/**
 * Sets wallpaper to one of the wallpapers displayed in wallpaper picker. If
 * the wallpaper download fails, retry one hour later. Wallpapers that are
 * disabled for surprise me are excluded.
 * @param {string} dateString String representation of current local date.
 * @private
 */
SurpriseWallpaper.prototype.setRandomWallpaper_ = function(dateString) {
  var self = this;
  Constants.WallpaperLocalStorage.get(Constants.AccessLocalManifestKey,
                                      function(items) {
    var manifest = items[Constants.AccessLocalManifestKey];
    if (manifest && manifest.wallpaper_list) {
      var filtered = manifest.wallpaper_list.filter(function(element) {
        // Older version manifest do not have available_for_surprise_me field.
        // In this case, no wallpaper should be filtered out.
        return element.available_for_surprise_me ||
            element.available_for_surprise_me == undefined;
      });
      var index = Math.floor(Math.random() * filtered.length);
      var wallpaper = filtered[index];
      var wallpaperURL = wallpaper.base_url + Constants.HighResolutionSuffix;
      var onSuccess = function() {
        WallpaperUtil.saveWallpaperInfo(wallpaperURL, wallpaper.default_layout,
            Constants.WallpaperSourceEnum.Online);
        WallpaperUtil.saveToLocalStorage(
            Constants.AccessLastSurpriseWallpaperChangedDate,
            dateString, function() {
              WallpaperUtil.saveToSyncStorage(
                Constants.AccessLastSurpriseWallpaperChangedDate,
                dateString);
            });
      };
      WallpaperUtil.setOnlineWallpaper(wallpaperURL, wallpaper.default_layout,
          onSuccess, self.retryLater_.bind(self));
    }
  });
};

/**
 * Sets wallpaper to the wallpaper specified by item from rss. If downloading
 * the wallpaper fails, retry one hour later.
 * @param {Element} item The wallpaper rss item element.
 * @param {function} onSuccess Success callback.
 * @param {function} onFailure Failure callback.
 * @private
 */
SurpriseWallpaper.prototype.setWallpaperFromRssItem_ = function(item,
                                                                onSuccess,
                                                                onFailure) {
  var url = item.querySelector('link').textContent;
  var layout = item.getElementsByTagNameNS(
        Constants.WallpaperNameSpaceURI, 'layout')[0].textContent;
  var self = this;
  WallpaperUtil.fetchURL(url, 'arraybuffer', function(xhr) {
    if (xhr.response != null) {
      chrome.wallpaperPrivate.setCustomWallpaper(xhr.response, layout, false,
                                                 'surprise_wallpaper',
                                                 onSuccess);
      WallpaperUtil.saveWallpaperInfo(url, layout,
                                      Constants.WallpaperSourceEnum.Online);
      var dateString = new Date().toDateString();
      WallpaperUtil.saveToLocalStorage(
          Constants.AccessLastSurpriseWallpaperChangedDate,
          dateString, function() {
            WallpaperUtil.saveToSyncStorage(
              Constants.AccessLastSurpriseWallpaperChangedDate, dataString);
          });
    } else {
      self.updateRandomWallpaper_();
    }
  }, onFailure);
};

/**
 * Disables the wallpaper surprise me feature. Clear all alarms and states.
 */
SurpriseWallpaper.prototype.disable = function() {
  chrome.alarms.clearAll();
  // Makes last changed date invalid.
  WallpaperUtil.saveToLocalStorage(
      Constants.AccessLastSurpriseWallpaperChangedDate, '', function() {
    WallpaperUtil.saveToSyncStorage(
      Constants.AccessLastSurpriseWallpaperChangedDate, '');
  });
};

/**
 * Changes current wallpaper and sets up an alarm to schedule next change around
 * midnight.
 */
SurpriseWallpaper.prototype.next = function() {
  var nextUpdate = this.nextUpdateTime(new Date());
  chrome.alarms.create({when: nextUpdate});
  this.tryChangeWallpaper();
};

/**
 * Calculates when the next wallpaper change should be triggered.
 * @param {Date} now Current time.
 * @return {number} The time when next wallpaper change should happen.
 */
SurpriseWallpaper.prototype.nextUpdateTime = function(now) {
  var nextUpdate = new Date(now.setDate(now.getDate() + 1)).toDateString();
  return new Date(nextUpdate).getTime();
};

chrome.app.runtime.onLaunched.addListener(function() {
  if (wallpaperPickerWindow && !wallpaperPickerWindow.contentWindow.closed) {
    wallpaperPickerWindow.focus();
    chrome.wallpaperPrivate.minimizeInactiveWindows();
    return;
  }

  chrome.app.window.create('main.html', {
    frame: 'none',
    width: WALLPAPER_PICKER_WIDTH,
    height: WALLPAPER_PICKER_HEIGHT,
    resizable: false,
    alphaEnabled: true
  }, function(w) {
    wallpaperPickerWindow = w;
    chrome.wallpaperPrivate.minimizeInactiveWindows();
    w.onClosed.addListener(function() {
      chrome.wallpaperPrivate.restoreMinimizedWindows();
    });
    WallpaperUtil.testSendMessage('wallpaper-window-created');
  });
});

chrome.syncFileSystem.onFileStatusChanged.addListener(function(detail) {
  WallpaperUtil.enabledSyncThemesCallback(function(syncEnabled) {
    if (!syncEnabled)
      return;
    if (detail.status == 'synced') {
      if (detail.direction == 'remote_to_local') {
        if (detail.action == 'added') {
          Constants.WallpaperLocalStorage.get(
              Constants.AccessLocalWallpaperInfoKey,
              function(items) {
                var localData = items[Constants.AccessLocalWallpaperInfoKey];
                if (localData && localData.url == detail.fileEntry.name &&
                    localData.source == Constants.WallpaperSourceEnum.Custom) {
                  WallpaperUtil.setCustomWallpaperFromSyncFS(localData.url,
                                                             localData.layout);
                } else if (!localData || localData.url !=
                           detail.fileEntry.name.replace(
                               Constants.CustomWallpaperThumbnailSuffix, '')) {
                  // localData might be null on a powerwashed device.
                  WallpaperUtil.storeWallpaperFromSyncFSToLocalFS(
                      detail.fileEntry);
                }
             });
        } else if (detail.action == 'deleted') {
          var fileName = detail.fileEntry.name.replace(
              Constants.CustomWallpaperThumbnailSuffix, '');
          WallpaperUtil.deleteWallpaperFromLocalFS(fileName);
        }
      } else {  // detail.direction == 'local_to_remote'
        if (detail.action == 'deleted') {
          WallpaperUtil.deleteWallpaperFromSyncFS(detail.fileEntry.name);
          WallpaperUtil.deleteWallpaperFromLocalFS(detail.fileEntry.name);
        }
      }
    }
  });
});

chrome.storage.onChanged.addListener(function(changes, namespace) {
  WallpaperUtil.enabledSyncThemesCallback(function(syncEnabled) {
    if (syncEnabled) {
      // If sync theme is enabled, use values from chrome.storage.sync to sync
      // wallpaper changes.
      WallpaperUtil.requestSyncFS(function() {});
      if (changes[Constants.AccessSyncSurpriseMeEnabledKey]) {
        if (changes[Constants.AccessSyncSurpriseMeEnabledKey].newValue) {
          SurpriseWallpaper.getInstance().next();
        } else {
          SurpriseWallpaper.getInstance().disable();
        }
      }

      if (changes[Constants.AccessLocalWallpaperInfoKey]) {
        // If the old wallpaper is a third party wallpaper we should remove it
        // from the local & sync file system to free space.
        var oldInfo = changes[Constants.AccessLocalWallpaperInfoKey].oldValue;
        if (oldInfo.url.indexOf(Constants.ThirdPartyWallpaperPrefix) != -1) {
          WallpaperUtil.deleteWallpaperFromLocalFS(oldInfo.url);
          WallpaperUtil.deleteWallpaperFromSyncFS(oldInfo.url);
        }
      }

      if (changes[Constants.AccessSyncWallpaperInfoKey]) {
        var syncInfo = changes[Constants.AccessSyncWallpaperInfoKey].newValue;

        Constants.WallpaperSyncStorage.get(
            Constants.AccessSyncSurpriseMeEnabledKey, function(enabledItems) {
          var syncSurpriseMeEnabled =
              enabledItems[Constants.AccessSyncSurpriseMeEnabledKey];

          Constants.WallpaperSyncStorage.get(
              Constants.AccessLastSurpriseWallpaperChangedDate,
              function(items) {
            var syncLastSurpriseMeChangedDate =
                items[Constants.AccessLastSurpriseWallpaperChangedDate];

            var today = new Date().toDateString();
            // If SurpriseMe is enabled and surprise wallpaper hasn't been
            // changed today, we should not sync the change, instead onAlarm()
            // will be triggered to update a surprise me wallpaper.
            if (!syncSurpriseMeEnabled ||
                (syncSurpriseMeEnabled &&
                 syncLastSurpriseMeChangedDate == today)) {
              Constants.WallpaperLocalStorage.get(
                  Constants.AccessLocalWallpaperInfoKey, function(infoItems) {
                var localInfo =
                    infoItems[Constants.AccessLocalWallpaperInfoKey];
                // Normally, the wallpaper info saved in local storage and sync
                // storage are the same. If the synced value changed by sync
                // service, they may different. In that case, change wallpaper
                // to the one saved in sync storage and update the local value.
                if (localInfo == undefined ||
                    localInfo.url != syncInfo.url ||
                    localInfo.layout != syncInfo.layout ||
                    localInfo.source != syncInfo.source) {
                  if (syncInfo.source == Constants.WallpaperSourceEnum.Online) {
                    // TODO(bshe): Consider schedule an alarm to set online
                    // wallpaper later when failed. Note that we need to cancel
                    // the retry if user set another wallpaper before retry
                    // alarm invoked.
                    WallpaperUtil.setOnlineWallpaper(syncInfo.url,
                        syncInfo.layout, function() {}, function() {});
                  } else if (syncInfo.source ==
                             Constants.WallpaperSourceEnum.Custom) {
                    WallpaperUtil.setCustomWallpaperFromSyncFS(syncInfo.url,
                                                               syncInfo.layout);
                  } else if (syncInfo.source ==
                              Constants.WallpaperSourceEnum.Default) {
                    chrome.wallpaperPrivate.resetWallpaper();
                  }

                  // If the old wallpaper is a third party wallpaper we should
                  // remove it from the local & sync file system to free space.
                  if (localInfo && localInfo.url.indexOf(
                      Constants.ThirdPartyWallpaperPrefix) != -1) {
                    WallpaperUtil.deleteWallpaperFromLocalFS(localInfo.url);
                    WallpaperUtil.deleteWallpaperFromSyncFS(localInfo.url);
                  }

                  WallpaperUtil.saveToLocalStorage(
                      Constants.AccessLocalWallpaperInfoKey, syncInfo);
                }
              });
            }
          });
        });
      }
    } else {
      // If sync theme is disabled, use values from chrome.storage.local to
      // track wallpaper changes.
      if (changes[Constants.AccessLocalSurpriseMeEnabledKey]) {
        if (changes[Constants.AccessLocalSurpriseMeEnabledKey].newValue) {
          SurpriseWallpaper.getInstance().next();
        } else {
          SurpriseWallpaper.getInstance().disable();
        }
      }
    }
  });
});

chrome.alarms.onAlarm.addListener(function() {
  SurpriseWallpaper.getInstance().next();
});

chrome.wallpaperPrivate.onWallpaperChangedBy3rdParty.addListener(function(
    wallpaper, thumbnail, layout) {
  WallpaperUtil.saveToLocalStorage(
      Constants.AccessLocalSurpriseMeEnabledKey, false, function() {
    WallpaperUtil.saveToSyncStorage(Constants.AccessSyncSurpriseMeEnabledKey,
                                    false);
  });
  SurpriseWallpaper.getInstance().disable();

  // Make third party wallpaper syncable through different devices.
  // TODO(xdai): also sync the third party app name.
  var filename = Constants.ThirdPartyWallpaperPrefix + new Date().getTime();
  var thumbnailFilename = filename + Constants.CustomWallpaperThumbnailSuffix;
  WallpaperUtil.storeWallpaperToSyncFS(filename, wallpaper);
  WallpaperUtil.storeWallpaperToSyncFS(thumbnailFilename, thumbnail);
  WallpaperUtil.saveWallpaperInfo(filename, layout,
                                  Constants.WallpaperSourceEnum.Custom);
});
