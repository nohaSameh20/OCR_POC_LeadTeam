//
//  LTOcrEngineManager.h
//  Leadtools.Ocr
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools.Ocr/LTOcrEngine.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTOcrEngineManager : NSObject // STATIC CLASS

+ (LTOcrEngine *)createEngine:(LTOcrEngineType)engineType;

- (instancetype)init __unavailable;

@end

NS_ASSUME_NONNULL_END
