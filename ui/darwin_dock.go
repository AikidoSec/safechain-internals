//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static void setActivationPolicyAccessory(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		[[NSApplication sharedApplication] setActivationPolicy:NSApplicationActivationPolicyAccessory];
	});
}
*/
import "C"

func keepDockHidden() {
	C.setActivationPolicyAccessory()
}
