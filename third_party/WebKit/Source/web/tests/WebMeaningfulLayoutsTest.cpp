// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/dom/Document.h"
#include "platform/testing/UnitTestHelpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "web/tests/sim/SimCompositor.h"
#include "web/tests/sim/SimDisplayItemList.h"
#include "web/tests/sim/SimRequest.h"
#include "web/tests/sim/SimTest.h"

namespace blink {

class WebMeaningfulLayoutsTest : public SimTest {
};

TEST_F(WebMeaningfulLayoutsTest, VisuallyNonEmptyTextCharacters)
{
    SimRequest mainResource("https://example.com/index.html", "text/html");

    loadURL("https://example.com/index.html");

    mainResource.start();

    // Write 201 characters.
    const char* tenCharacters = "0123456789";
    for (int i = 0; i < 20; ++i)
        mainResource.write(tenCharacters);
    mainResource.write("!");

    mainResource.finish();

    compositor().beginFrame();

    EXPECT_TRUE(webViewClient().hadVisuallyNonEmptyLayout());
}

TEST_F(WebMeaningfulLayoutsTest, VisuallyNonEmptyTextCharactersEventually)
{
    SimRequest mainResource("https://example.com/index.html", "text/html");

    loadURL("https://example.com/index.html");

    mainResource.start();

    // Write 200 characters.
    const char* tenCharacters = "0123456789";
    for (int i = 0; i < 20; ++i)
        mainResource.write(tenCharacters);

    // Pump a frame mid-load.
    compositor().beginFrame();

    EXPECT_FALSE(webViewClient().hadVisuallyNonEmptyLayout());

    // Write more than 200 characters.
    mainResource.write("!");

    mainResource.finish();

    // setting visually non-empty happens when the parsing finishes,
    // not as the character count goes over 200.
    compositor().beginFrame();

    EXPECT_TRUE(webViewClient().hadVisuallyNonEmptyLayout());
}

// TODO(dglazkov): Write pixel-count and canvas-based VisuallyNonEmpty tests

TEST_F(WebMeaningfulLayoutsTest, VisuallyNonEmptyMissingPump)
{
    SimRequest mainResource("https://example.com/index.html", "text/html");

    loadURL("https://example.com/index.html");

    mainResource.start();

    // Write <200 characters.
    mainResource.write("less than 200 characters.");

    compositor().beginFrame();

    mainResource.finish();

    // Even though the layout state is clean ...
    EXPECT_TRUE(document().lifecycle().state() >= DocumentLifecycle::LayoutClean);

    // We should still generate a request for another (possibly last) frame.
    EXPECT_TRUE(compositor().needsAnimate());

    // ... which we (the scheduler) happily provide.
    compositor().beginFrame();

    // ... which correctly signals the VisuallyNonEmpty.
    EXPECT_TRUE(webViewClient().hadVisuallyNonEmptyLayout());
}

TEST_F(WebMeaningfulLayoutsTest, FinishedParsing)
{
    SimRequest mainResource("https://example.com/index.html", "text/html");

    loadURL("https://example.com/index.html");

    mainResource.start();

    mainResource.write("content");

    mainResource.finish();

    compositor().beginFrame();

    EXPECT_TRUE(webViewClient().hadFinishedParsingLayout());
}

TEST_F(WebMeaningfulLayoutsTest, FinishedLoading)
{
    SimRequest mainResource("https://example.com/index.html", "text/html");

    loadURL("https://example.com/index.html");

    mainResource.start();

    mainResource.write("content");

    mainResource.finish();

    compositor().beginFrame();

    EXPECT_TRUE(webViewClient().hadFinishedLoadingLayout());
}

TEST_F(WebMeaningfulLayoutsTest, FinishedParsingThenLoading)
{
    SimRequest mainResource("https://example.com/index.html", "text/html");
    SimRequest imageResource("https://example.com/cat.png", "image/png");

    loadURL("https://example.com/index.html");

    mainResource.start();

    mainResource.write("<img src=cat.png>");

    mainResource.finish();

    compositor().beginFrame();

    EXPECT_TRUE(webViewClient().hadFinishedParsingLayout());
    EXPECT_FALSE(webViewClient().hadFinishedLoadingLayout());

    imageResource.complete("image data");

    // Pump the message loop to process the image loading task.
    testing::runPendingTasks();

    compositor().beginFrame();

    EXPECT_TRUE(webViewClient().hadFinishedLoadingLayout());
}

}
