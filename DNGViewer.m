// DNGViewer.m — crash oracle для CVE-2025-43300 (Quarkslab, macOS).
//
// Запуск (macOS 15.6 = vulnerable, 15.6.1 = patched control):
//   clang -framework Foundation -framework AppKit -framework CoreImage -o DNGViewer DNGViewer.m
//   ./DNGViewer payload.dng
//
// Ожидаем: CRASH (OOB write) на 15.6, нет crash на 15.6.1.
// Для debug: SIP off, LLDB breakpoints на CDNGLosslessJpegUnpacker.

#import <Foundation/Foundation.h>
#import <CoreImage/CoreImage.h>
#import <AppKit/AppKit.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            NSLog(@"Usage: %s <input.dng>", argv[0]);
            return 1;
        }

        NSString *inputPath = [NSString stringWithUTF8String:argv[1]];
        NSURL *inputURL = [NSURL fileURLWithPath:inputPath];

        // Create CIRawFilter with the DNG file
        CIFilter *rawFilter = [CIFilter filterWithImageURL:inputURL
                                                   options:@{ (NSString *)kCIImageApplyOrientationProperty: @NO }];
        if (!rawFilter) {
            NSLog(@"Failed to create CIRawFilter for file: %@", inputURL);
            return 1;
        }

        // Get output CIImage
        CIImage *ciImage = [rawFilter valueForKey:kCIOutputImageKey];
        if (!ciImage) {
            NSLog(@"Failed to process image.");
            return 1;
        }

        // Create CIContext and generate CGImage
        CIContext *context = [CIContext contextWithOptions:nil];
        CGRect extent = [ciImage extent];
        CGImageRef cgImage = [context createCGImage:ciImage fromRect:extent];
        if (!cgImage) {
            NSLog(@"Failed to create CGImage.");
            return 1;
        }

        // Set up the application and run loop
        [NSApplication sharedApplication];

        NSImage *nsImage = [[NSImage alloc] initWithCGImage:cgImage size:NSZeroSize];
        CGImageRelease(cgImage);

        NSRect frame = NSMakeRect(0, 0, nsImage.size.width, nsImage.size.height);
        NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
                                                       styleMask:(NSWindowStyleMaskTitled |
                                                                  NSWindowStyleMaskClosable |
                                                                  NSWindowStyleMaskResizable)
                                                         backing:NSBackingStoreBuffered
                                                         defer:NO];
        [window setTitle:@"DNG Image Viewer"];

        NSImageView *imageView = [[NSImageView alloc] initWithFrame:frame];
        [imageView setImage:nsImage];
        [imageView setImageScaling:NSImageScaleProportionallyUpOrDown];
        [window.contentView addSubview:imageView];

        [window center];
        [window makeKeyAndOrderFront:nil];
    }

    return 0;
}
