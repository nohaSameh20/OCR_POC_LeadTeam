//
//  LTGetBackgroundColorCommand.h
//  Leadtools.ImageProcessing.Core
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools/LTRasterCommand.h>
#import <Leadtools/LTRasterColor.h>
#import <Leadtools/LTPrimitives.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTGetBackgroundColorCommand : LTRasterCommand

@property (nonatomic, strong, readonly) NSMutableArray<NSValue *> *rectangles; //LeadRect
@property (nonatomic, strong, readonly) NSMutableArray<LTRasterColor *> *backgroundColors;

@end

NS_ASSUME_NONNULL_END
