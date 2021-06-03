//
//  LTKernelDetectGlareCommand.h
//  Leadtools.ImageProcessing.Kernel
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools/LTRasterCommand.h>
#import <Leadtools/LTPrimitives.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTKernelDetectGlareCommand : LTRasterCommand

@property (nonatomic, assign, readonly) LeadRect glareArea;

@end

NS_ASSUME_NONNULL_END
