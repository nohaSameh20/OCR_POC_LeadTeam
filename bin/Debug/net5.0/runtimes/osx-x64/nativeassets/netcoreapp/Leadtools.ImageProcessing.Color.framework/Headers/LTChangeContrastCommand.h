//
//  LTChangeContrastCommand.h
//  Leadtools.ImageProcessing.Color
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools/LTRasterCommand.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTChangeContrastCommand : LTRasterCommand

@property (nonatomic, assign) NSInteger contrast;

- (instancetype)initWithContrast:(NSInteger)contrast NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
