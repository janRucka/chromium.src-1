// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/frame/browser_view_layout.h"

#include "base/macros.h"
#include "base/observer_list.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_finder.h"
#include "chrome/browser/ui/browser_window.h"
#include "chrome/browser/ui/find_bar/find_bar.h"
#include "chrome/browser/ui/find_bar/find_bar_controller.h"
#include "chrome/browser/ui/layout_constants.h"
#include "chrome/browser/ui/search/search_model.h"
#include "chrome/browser/ui/views/bookmarks/bookmark_bar_view.h"
#include "chrome/browser/ui/views/download/download_shelf_view.h"
#include "chrome/browser/ui/views/exclusive_access_bubble_views.h"
#include "chrome/browser/ui/views/frame/browser_view_layout_delegate.h"
#include "chrome/browser/ui/views/frame/contents_layout_manager.h"
#include "chrome/browser/ui/views/frame/immersive_mode_controller.h"
#include "chrome/browser/ui/views/frame/top_container_view.h"
#include "chrome/browser/ui/views/infobars/infobar_container_view.h"
#include "chrome/browser/ui/views/tabs/tab_strip.h"
#include "components/web_modal/web_contents_modal_dialog_host.h"
#include "ui/base/hit_test.h"
#include "ui/base/resource/material_design/material_design_controller.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/scrollbar_size.h"
#include "ui/views/controls/webview/webview.h"
#include "ui/views/widget/widget.h"
#include "ui/views/window/client_view.h"

using views::View;
using web_modal::WebContentsModalDialogHost;
using web_modal::ModalDialogHostObserver;

namespace {

// The visible height of the shadow above the tabs. Clicks in this area are
// treated as clicks to the frame, rather than clicks to the tab.
const int kTabShadowSize = 2;
// The number of pixels the constrained window should overlap the bottom
// of the omnibox.
const int kConstrainedWindowOverlap = 3;

// Combines View::ConvertPointToTarget and View::HitTest for a given |point|.
// Converts |point| from |src| to |dst| and hit tests it against |dst|. The
// converted |point| can then be retrieved and used for additional tests.
bool ConvertedHitTest(views::View* src, views::View* dst, gfx::Point* point) {
  DCHECK(src);
  DCHECK(dst);
  DCHECK(point);
  views::View::ConvertPointToTarget(src, dst, point);
  return dst->HitTestPoint(*point);
}

}  // namespace

class BrowserViewLayout::WebContentsModalDialogHostViews
    : public WebContentsModalDialogHost {
 public:
  explicit WebContentsModalDialogHostViews(
      BrowserViewLayout* browser_view_layout)
          : browser_view_layout_(browser_view_layout) {
  }

  ~WebContentsModalDialogHostViews() override {
    FOR_EACH_OBSERVER(ModalDialogHostObserver,
                      observer_list_,
                      OnHostDestroying());
  }

  void NotifyPositionRequiresUpdate() {
    FOR_EACH_OBSERVER(ModalDialogHostObserver,
                      observer_list_,
                      OnPositionRequiresUpdate());
  }

  gfx::Point GetDialogPosition(const gfx::Size& size) override {
    views::View* view = browser_view_layout_->contents_container_;
    gfx::Rect content_area = view->ConvertRectToWidget(view->GetLocalBounds());
    const int middle_x = content_area.x() + content_area.width() / 2;
    const int top = browser_view_layout_->web_contents_modal_dialog_top_y_;
    return gfx::Point(middle_x - size.width() / 2, top);
  }

  gfx::Size GetMaximumDialogSize() override {
    views::View* view = browser_view_layout_->contents_container_;
    gfx::Rect content_area = view->ConvertRectToWidget(view->GetLocalBounds());
    const int top = browser_view_layout_->web_contents_modal_dialog_top_y_;
    return gfx::Size(content_area.width(), content_area.bottom() - top);
  }

 private:
  gfx::NativeView GetHostView() const override {
    gfx::NativeWindow window =
        browser_view_layout_->browser()->window()->GetNativeWindow();
    return views::Widget::GetWidgetForNativeWindow(window)->GetNativeView();
  }

  // Add/remove observer.
  void AddObserver(ModalDialogHostObserver* observer) override {
    observer_list_.AddObserver(observer);
  }
  void RemoveObserver(ModalDialogHostObserver* observer) override {
    observer_list_.RemoveObserver(observer);
  }

  BrowserViewLayout* const browser_view_layout_;

  base::ObserverList<ModalDialogHostObserver> observer_list_;

  DISALLOW_COPY_AND_ASSIGN(WebContentsModalDialogHostViews);
};

////////////////////////////////////////////////////////////////////////////////
// BrowserViewLayout, public:

BrowserViewLayout::BrowserViewLayout()
    : browser_(nullptr),
      browser_view_(nullptr),
      top_container_(nullptr),
      tab_strip_(nullptr),
      toolbar_(nullptr),
      bookmark_bar_(nullptr),
      infobar_container_(nullptr),
      contents_container_(nullptr),
      contents_layout_manager_(nullptr),
      download_shelf_(nullptr),
      immersive_mode_controller_(nullptr),
      dialog_host_(new WebContentsModalDialogHostViews(this)),
      web_contents_modal_dialog_top_y_(-1) {}

BrowserViewLayout::~BrowserViewLayout() {
}

void BrowserViewLayout::Init(
    BrowserViewLayoutDelegate* delegate,
    Browser* browser,
    views::ClientView* browser_view,
    views::View* top_container,
    TabStrip* tab_strip,
    views::View* toolbar,
    InfoBarContainerView* infobar_container,
    views::View* contents_container,
    ContentsLayoutManager* contents_layout_manager,
    ImmersiveModeController* immersive_mode_controller) {
  delegate_.reset(delegate);
  browser_ = browser;
  browser_view_ = browser_view;
  top_container_ = top_container;
  tab_strip_ = tab_strip;
  toolbar_ = toolbar;
  infobar_container_ = infobar_container;
  contents_container_ = contents_container;
  contents_layout_manager_ = contents_layout_manager;
  immersive_mode_controller_ = immersive_mode_controller;
}

WebContentsModalDialogHost*
    BrowserViewLayout::GetWebContentsModalDialogHost() {
  return dialog_host_.get();
}

gfx::Size BrowserViewLayout::GetMinimumSize() {
  gfx::Size tabstrip_size(
      browser()->SupportsWindowFeature(Browser::FEATURE_TABSTRIP) ?
      tab_strip_->GetMinimumSize() : gfx::Size());
  gfx::Size toolbar_size(
      (browser()->SupportsWindowFeature(Browser::FEATURE_TOOLBAR) ||
       browser()->SupportsWindowFeature(Browser::FEATURE_LOCATIONBAR)) ?
           toolbar_->GetMinimumSize() : gfx::Size());
  if (tabstrip_size.height() && toolbar_size.height())
    toolbar_size.Enlarge(0, -GetLayoutConstant(TABSTRIP_TOOLBAR_OVERLAP));
  gfx::Size bookmark_bar_size;
  if (bookmark_bar_ &&
      bookmark_bar_->visible() &&
      browser()->SupportsWindowFeature(Browser::FEATURE_BOOKMARKBAR)) {
    bookmark_bar_size = bookmark_bar_->GetMinimumSize();
    bookmark_bar_size.Enlarge(0, -bookmark_bar_->GetToolbarOverlap());
  }
  gfx::Size infobar_container_size(infobar_container_->GetMinimumSize());
  // TODO: Adjust the minimum height for the find bar.

  gfx::Size contents_size(contents_container_->GetMinimumSize());

  int min_height = delegate_->GetTopInsetInBrowserView(false) +
      tabstrip_size.height() + toolbar_size.height() +
      bookmark_bar_size.height() + infobar_container_size.height() +
      contents_size.height();
  int widths[] = {
        tabstrip_size.width(),
        toolbar_size.width(),
        bookmark_bar_size.width(),
        infobar_container_size.width(),
        contents_size.width() };
  int min_width = *std::max_element(&widths[0], &widths[arraysize(widths)]);
  return gfx::Size(min_width, min_height);
}

gfx::Rect BrowserViewLayout::GetFindBarBoundingBox() const {
  // This function returns the area the Find Bar can be laid out within. This
  // basically implies the "user-perceived content area" of the browser
  // window excluding the vertical scrollbar. The "user-perceived content area"
  // excludes the detached bookmark bar (in the New Tab case) and any infobars
  // since they are not _visually_ connected to the Toolbar.

  // First determine the bounding box of the content area in Widget
  // coordinates.
  gfx::Rect bounding_box = contents_container_->ConvertRectToWidget(
      contents_container_->GetLocalBounds());

  gfx::Rect top_container_bounds = top_container_->ConvertRectToWidget(
      top_container_->GetLocalBounds());

  int find_bar_y = 0;
  if (immersive_mode_controller_->IsEnabled() &&
      !immersive_mode_controller_->IsRevealed()) {
    // Position the find bar exactly below the top container. In immersive
    // fullscreen, when the top-of-window views are not revealed, only the
    // miniature immersive style tab strip is visible. Do not overlap the
    // find bar and the tab strip.
    find_bar_y = top_container_bounds.bottom();
  } else {
    // Overlap the find bar atop |top_container_|.
    // The find bar should look connected to the top container when material
    // design is not enabled.
    find_bar_y = top_container_bounds.bottom() -
                 GetLayoutConstant(FIND_BAR_TOOLBAR_OVERLAP);
  }

  // Grow the height of |bounding_box| by the height of any elements between
  // the top container and |contents_container_| such as the detached bookmark
  // bar and any infobars.
  int height_delta = bounding_box.y() - find_bar_y;
  bounding_box.set_y(find_bar_y);
  bounding_box.set_height(std::max(0, bounding_box.height() + height_delta));

  // Finally decrease the width of the bounding box by the width of
  // the vertical scroll bar.
  int scrollbar_width = gfx::scrollbar_size();
  bounding_box.set_width(std::max(0, bounding_box.width() - scrollbar_width));
  if (base::i18n::IsRTL())
    bounding_box.set_x(bounding_box.x() + scrollbar_width);

  return bounding_box;
}

int BrowserViewLayout::NonClientHitTest(const gfx::Point& point) {
  // Since the TabStrip only renders in some parts of the top of the window,
  // the un-obscured area is considered to be part of the non-client caption
  // area of the window. So we need to treat hit-tests in these regions as
  // hit-tests of the titlebar.

  views::View* parent = browser_view_->parent();

  gfx::Point point_in_browser_view_coords(point);
  views::View::ConvertPointToTarget(
      parent, browser_view_, &point_in_browser_view_coords);
  gfx::Point test_point(point);

  // Determine if the TabStrip exists and is capable of being clicked on. We
  // might be a popup window without a TabStrip.
  if (delegate_->IsTabStripVisible()) {
    // See if the mouse pointer is within the bounds of the TabStrip.
    if (ConvertedHitTest(parent, tab_strip_, &test_point)) {
      if (tab_strip_->IsPositionInWindowCaption(test_point))
        return HTCAPTION;
      return HTCLIENT;
    }

    // The top few pixels of the TabStrip are a drop-shadow - as we're pretty
    // starved of dragable area, let's give it to window dragging (this also
    // makes sense visually).
    views::Widget* widget = browser_view_->GetWidget();
    if (!(widget->IsMaximized() || widget->IsFullscreen()) &&
        (point_in_browser_view_coords.y() <
            (tab_strip_->y() + kTabShadowSize))) {
      // We return HTNOWHERE as this is a signal to our containing
      // NonClientView that it should figure out what the correct hit-test
      // code is given the mouse position...
      return HTNOWHERE;
    }
  }

  // If the point's y coordinate is below the top of the toolbar and otherwise
  // within the bounds of this view, the point is considered to be within the
  // client area.
  gfx::Rect bv_bounds = browser_view_->bounds();
  bv_bounds.Offset(0, toolbar_->y());
  bv_bounds.set_height(bv_bounds.height() - toolbar_->y());
  if (bv_bounds.Contains(point))
    return HTCLIENT;

  // If the point's y coordinate is above the top of the toolbar, but not
  // over the tabstrip (per previous checking in this function), then we
  // consider it in the window caption (e.g. the area to the right of the
  // tabstrip underneath the window controls). However, note that we DO NOT
  // return HTCAPTION here, because when the window is maximized the window
  // controls will fall into this space (since the BrowserView is sized to
  // entire size of the window at that point), and the HTCAPTION value will
  // cause the window controls not to work. So we return HTNOWHERE so that the
  // caller will hit-test the window controls before finally falling back to
  // HTCAPTION.
  bv_bounds = browser_view_->bounds();
  bv_bounds.set_height(toolbar_->y());
  if (bv_bounds.Contains(point))
    return HTNOWHERE;

  // If the point is somewhere else, delegate to the default implementation.
  return browser_view_->views::ClientView::NonClientHitTest(point);
}

//////////////////////////////////////////////////////////////////////////////
// BrowserViewLayout, views::LayoutManager implementation:

void BrowserViewLayout::Layout(views::View* browser_view) {
  vertical_layout_rect_ = browser_view->GetLocalBounds();
  int top = LayoutTabStripRegion(delegate_->GetTopInsetInBrowserView(false));
  if (delegate_->IsTabStripVisible()) {
    // By passing true to GetTopInsetInBrowserView(), we position the tab
    // background to vertically align with the frame background image of a
    // restored-mode frame, even in a maximized window.  Then in the frame code,
    // we position the frame so the portion of the image that's behind the
    // restored-mode tabstrip is always behind the tabstrip.  Together these
    // ensure that the tab and frame images are always aligned, and that their
    // relative alignment with the toolbar image is always the same, so themes
    // which try to align all three will look correct in both restored and
    // maximized windows.
    tab_strip_->SetBackgroundOffset(gfx::Point(
        tab_strip_->GetMirroredX() + browser_view_->GetMirroredX() +
            delegate_->GetThemeBackgroundXInset(),
        browser_view_->y() + delegate_->GetTopInsetInBrowserView(true)));
  }
  top = LayoutToolbar(top);

  top = LayoutBookmarkAndInfoBars(top, browser_view->y());

  // Top container requires updated toolbar and bookmark bar to compute bounds.
  UpdateTopContainerBounds();

  int bottom = LayoutDownloadShelf(browser_view->height());
  // Treat a detached bookmark bar as if the web contents container is shifted
  // upwards and overlaps it.
  int active_top_margin = GetContentsOffsetForBookmarkBar();
  contents_layout_manager_->SetActiveTopMargin(active_top_margin);
  top -= active_top_margin;
  LayoutContentsContainerView(top, bottom);

  // This must be done _after_ we lay out the WebContents since this
  // code calls back into us to find the bounding box the find bar
  // must be laid out within, and that code depends on the
  // TabContentsContainer's bounds being up to date.
  if (browser()->HasFindBarController()) {
    browser()->GetFindBarController()->find_bar()->MoveWindowIfNecessary(
        gfx::Rect());
  }

  // Adjust the fullscreen exit bubble bounds for |top_container_|'s new bounds.
  // This makes the fullscreen exit bubble look like it animates with
  // |top_container_| in immersive fullscreen.
  ExclusiveAccessBubbleViews* exclusive_access_bubble =
      delegate_->GetExclusiveAccessBubble();
  if (exclusive_access_bubble)
    exclusive_access_bubble->RepositionIfVisible();

  // Adjust any hosted dialogs if the browser's dialog hosting bounds changed.
  const gfx::Rect dialog_bounds(dialog_host_->GetDialogPosition(gfx::Size()),
                                dialog_host_->GetMaximumDialogSize());
  if (latest_dialog_bounds_ != dialog_bounds) {
    latest_dialog_bounds_ = dialog_bounds;
    dialog_host_->NotifyPositionRequiresUpdate();
  }
}

// Return the preferred size which is the size required to give each
// children their respective preferred size.
gfx::Size BrowserViewLayout::GetPreferredSize(const views::View* host) const {
  return gfx::Size();
}

//////////////////////////////////////////////////////////////////////////////
// BrowserViewLayout, private:

int BrowserViewLayout::LayoutTabStripRegion(int top) {
  if (!delegate_->IsTabStripVisible()) {
    tab_strip_->SetVisible(false);
    tab_strip_->SetBounds(0, 0, 0, 0);
    return top;
  }
  // This retrieves the bounds for the tab strip based on whether or not we show
  // anything to the left of it, like the incognito avatar.
  gfx::Rect tabstrip_bounds(delegate_->GetBoundsForTabStripInBrowserView());

  tab_strip_->SetVisible(true);
  tab_strip_->SetBoundsRect(tabstrip_bounds);

  return tabstrip_bounds.bottom();
}

int BrowserViewLayout::LayoutToolbar(int top) {
  int browser_view_width = vertical_layout_rect_.width();
  bool toolbar_visible = delegate_->IsToolbarVisible();
  int y = top;
  y -= (toolbar_visible && delegate_->IsTabStripVisible()) ?
      GetLayoutConstant(TABSTRIP_TOOLBAR_OVERLAP) : 0;
  int height = toolbar_visible ? toolbar_->GetPreferredSize().height() : 0;
  toolbar_->SetVisible(toolbar_visible);
  toolbar_->SetBounds(vertical_layout_rect_.x(), y, browser_view_width, height);

  return y + height;
}

int BrowserViewLayout::LayoutBookmarkAndInfoBars(int top, int browser_view_y) {
  web_contents_modal_dialog_top_y_ =
      top + browser_view_y - kConstrainedWindowOverlap;

  if (bookmark_bar_) {
    // If we're showing the Bookmark bar in detached style, then we
    // need to show any Info bar _above_ the Bookmark bar, since the
    // Bookmark bar is styled to look like it's part of the page.
    if (bookmark_bar_->IsDetached()) {
      web_contents_modal_dialog_top_y_ =
          top + browser_view_y - kConstrainedWindowOverlap;
      return LayoutBookmarkBar(LayoutInfoBar(top));
    }
    // Otherwise, Bookmark bar first, Info bar second.
    top = std::max(toolbar_->bounds().bottom(), LayoutBookmarkBar(top));
  }

  return LayoutInfoBar(top);
}

int BrowserViewLayout::LayoutBookmarkBar(int top) {
  int y = top;
  if (!delegate_->IsBookmarkBarVisible()) {
    bookmark_bar_->SetVisible(false);
    // TODO(jamescook): Don't change the bookmark bar height when it is
    // invisible, so we can use its height for layout even in that state.
    bookmark_bar_->SetBounds(0, y, browser_view_->width(), 0);
    return y;
  }

  bookmark_bar_->set_infobar_visible(InfobarVisible());
  int bookmark_bar_height = bookmark_bar_->GetPreferredSize().height();
  y -= bookmark_bar_->GetToolbarOverlap();
  bookmark_bar_->SetBounds(vertical_layout_rect_.x(),
                           y,
                           vertical_layout_rect_.width(),
                           bookmark_bar_height);
  // Set visibility after setting bounds, as the visibility update uses the
  // bounds to determine if the mouse is hovering over a button.
  bookmark_bar_->SetVisible(true);
  return y + bookmark_bar_height;
}

int BrowserViewLayout::LayoutInfoBar(int top) {
  // In immersive fullscreen, the infobar always starts near the top of the
  // screen, just under the "light bar" rectangular stripes.
  if (immersive_mode_controller_->IsEnabled()) {
    top = browser_view_->y();
    if (!immersive_mode_controller_->ShouldHideTabIndicators())
      top += TabStrip::GetImmersiveHeight();
  }
  // Raise the |infobar_container_| by its vertical overlap.
  infobar_container_->SetVisible(InfobarVisible());
  int height;
  int overlapped_top = top - infobar_container_->GetVerticalOverlap(&height);
  infobar_container_->SetBounds(vertical_layout_rect_.x(),
                                overlapped_top,
                                vertical_layout_rect_.width(),
                                height);
  return overlapped_top + height;
}

void BrowserViewLayout::LayoutContentsContainerView(int top, int bottom) {
  // |contents_container_| contains web page contents and devtools.
  // See browser_view.h for details.
  gfx::Rect contents_container_bounds(vertical_layout_rect_.x(),
                                      top,
                                      vertical_layout_rect_.width(),
                                      std::max(0, bottom - top));
  contents_container_->SetBoundsRect(contents_container_bounds);
}

void BrowserViewLayout::UpdateTopContainerBounds() {
  // Set the bounds of the top container view such that it is tall enough to
  // fully show all of its children. In particular, the bottom of the bookmark
  // bar can be above the bottom of the toolbar while the bookmark bar is
  // animating. The top container view is positioned relative to the top of the
  // client view instead of relative to GetTopInsetInBrowserView() because the
  // top container view paints parts of the frame (title, window controls)
  // during an immersive fullscreen reveal.
  int height = 0;
  for (int i = 0; i < top_container_->child_count(); ++i) {
    views::View* child = top_container_->child_at(i);
    if (!child->visible())
      continue;
    int child_bottom = child->bounds().bottom();
    if (child_bottom > height)
      height = child_bottom;
  }

  // Ensure that the top container view reaches the topmost view in the
  // ClientView because the bounds of the top container view are used in
  // layout and we assume that this is the case.
  height = std::max(height, delegate_->GetTopInsetInBrowserView(false));

  gfx::Rect top_container_bounds(vertical_layout_rect_.width(), height);

  // If the immersive mode controller is animating the top container, it may be
  // partly offscreen.
  top_container_bounds.set_y(
      immersive_mode_controller_->GetTopContainerVerticalOffset(
          top_container_bounds.size()));
  top_container_->SetBoundsRect(top_container_bounds);
}

int BrowserViewLayout::GetContentsOffsetForBookmarkBar() {
  // If the bookmark bar is hidden or attached to the omnibox the web contents
  // will appear directly underneath it and does not need an offset.
  if (!bookmark_bar_ ||
      !delegate_->IsBookmarkBarVisible() ||
      !bookmark_bar_->IsDetached()) {
    return 0;
  }

  // Offset for the detached bookmark bar.
  return bookmark_bar_->height() -
      views::NonClientFrameView::kClientEdgeThickness;
}

int BrowserViewLayout::LayoutDownloadShelf(int bottom) {
  if (delegate_->DownloadShelfNeedsLayout()) {
    bool visible = browser()->SupportsWindowFeature(
        Browser::FEATURE_DOWNLOADSHELF);
    DCHECK(download_shelf_);
    int height = visible ? download_shelf_->GetPreferredSize().height() : 0;
    download_shelf_->SetVisible(visible);
    download_shelf_->SetBounds(vertical_layout_rect_.x(), bottom - height,
                               vertical_layout_rect_.width(), height);
    download_shelf_->Layout();
    bottom -= height;
  }
  return bottom;
}

bool BrowserViewLayout::InfobarVisible() const {
  // Cast to a views::View to access GetPreferredSize().
  views::View* infobar_container = infobar_container_;
  // NOTE: Can't check if the size IsEmpty() since it's always 0-width.
  return browser_->SupportsWindowFeature(Browser::FEATURE_INFOBAR) &&
      (infobar_container->GetPreferredSize().height() != 0);
}
