//
//  LTCodecsGifImageInfo.h
//  Leadtools.Codecs
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools/LTRasterColor.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTCodecsGifImageInfo : NSObject

@property (nonatomic, assign, readonly)           BOOL hasAnimationLoop;
@property (nonatomic, assign, readonly)           BOOL hasAnimationPalette;
@property (nonatomic, assign, readonly)           BOOL hasAnimationBackground;
@property (nonatomic, assign, readonly)           BOOL isInterlaced;

@property (nonatomic, assign, readonly)           NSInteger animationWidth;
@property (nonatomic, assign, readonly)           NSInteger animationHeight;

@property (nonatomic, assign, readonly)           NSUInteger animationLoop;

@property (nonatomic, copy, readonly)             LTRasterColor *animationBackground;
@property (nonatomic, strong, readonly, nullable) NSArray<LTRasterColor *> *animationPalette;

- (instancetype)init __unavailable;

@end

NS_ASSUME_NONNULL_END
